# -*- encoding: utf-8 -*-
"""
Provides a means of using a Redis server to implement dynamic addressing in a
manner that may be shared by multiple StaticDHCPd instances.

Persistent allocation is supported to ensure renewing and rebinding clients
receive the same address that they held previously.

The redis-py package is required.
This module does not support Sentinel or Cluster operation. Please feel free to
modify it to meet your own needs if this is something you require.

To use this module, add the following to conf.py's init() function:
    import staticDHCPd_extensions.redis_dynamic as redis_dynamic
    global _dynamic_pool
    _dynamic_pool = redis_dynamic.DynamicPool(<see its __init__ for parameters>)
    #Add 192.168.250.100-200
    _dynamic_pool.add_ips('192.168.250.{}'.format(i) for i in range(100, 201))
    
    #Expose its allocation table to the web interface
    callbacks.webAddMethod(
        '/yoursite/dynamic-pool/guest/0/leases', _dynamic_pool.show_leases_xhtml,
        hidden=False, module='guest-0', name='show leases',
        display_mode=callbacks.WEB_METHOD_TEMPLATE,
    )
    #You could also make it a permanent dashboard fixture:
    #callbacks.webAddDashboard('guest-0', 'leases', _dynamic_pool.show_leases_xhtml)
    #Add 'ordering=N', where N is a bias value, to change its position
    
    #And a CSV form, too, in case any automated processors need the data
    callbacks.webAddMethod(
        '/yoursite/dynamic-pool/guest/0/leases.csv', _dynamic_pool.show_leases_csv,
        hidden=False, module='guest-0', name='get leases (csv)',
        display_mode=callbacks.WEB_METHOD_RAW,
    )
    
And then add the following to conf.py's handleUnknownMAC():
    return _dynamic_pool.handle(method, packet, mac, client_ip)
    
    
Caution: if you need to reduce the set of available IPs, the entire hash under Redis
must be deleted or the list of registered IPs reset.

You can define as many pools as you'd like, but deciding how to use them is
more advanced than what will be covered here. Checking `giaddr` to determine
the relay-source is probably the most sane method, though.

Note that no validation is performed to ensure that the DHCP request was legal,
just that it was well-formed. Malicious clients cannot compromise the server,
but they can trigger DoS behaviour. Given that there's nothing to gain, however,
this is probably a non-issue.

Like staticDHCPd, this module under the GNU General Public License v3
(C) Neil Tallim, 2023 <neil.tallim@linux.com>
"""
import collections
import json
import logging
import time
import uuid

import redis

from staticdhcpdlib.databases.generic import Definition

from libpydhcpserver.dhcp_types.ipv4 import IPv4

_logger = logging.getLogger('extension.redis_dynamic')

_LeaseDefinition = collections.namedtuple('LeaseDefinition', ('ip', 'mac', 'expiration', 'last_seen'))
"""
Provides lease-definition information for an IP.

`ip` and `mac` are self-explanatory. `expiration` and `last_seen` are UNIX
timestamps.
"""

def _dynamic_method(method):
    """
    Handles locking and response-formatting; you do not need to study this,
    even if you are subclassing DynamicPool: you can just call the parent
    method normally and return its result.
    
    This is just a decorator.
    """
    def wrapped_method(self, *args, **kwargs):
        with self._lock:
            ip = method(self, *args, **kwargs)
            if ip:
                return Definition(
                    ip=ip, lease_time=self._lease_time, subnet=self._subnet, serial=self._serial,
                    hostname=(self._hostname_pattern.format(ip=str(ip).replace('.', '-'))),
                    gateways=self._gateway, subnet_mask=self._subnet_mask, broadcast_address=self._broadcast_address,
                    domain_name=self._domain_name, domain_name_servers=self._domain_name_servers, ntp_servers=self._ntp_servers,
                    extra=None,
                )
            return None
    return wrapped_method
    
class DynamicPool(object):
    def __init__(self,
        lease_key,
        subnet, serial, lease_time, hostname_prefix,
        subnet_mask=None, gateway=None, broadcast_address=None,
        domain_name=None, domain_name_servers=None, ntp_servers=None,
        **kwargs,
    ):
        """
        Initialises a new pool, containing no IPs. Call `add_ips()` to add some.
        
        For all Redis options, prefix the Redis connection argument with
        `redis_`, like `redis_host`, `redis_port`, and `redis_password`.
        
        `lease_key` is the key under which a hash containing all lease data will be
        held. This is done for performance and consistency purposes.
        
        `subnet` is any string you would like to use, like 'guest', and `serial`
        is its complement, an integer that lets you re-use the same subnet-name;
        guest network 0, 1, 2... What you use is up to you.
        
        `lease_time` is the number of seconds for which a lease will be offered.
        
        `hostname_prefix` is the leading part of the hostname to offer to
        clients; it should be something simple like 'guest-0'; it is completed
        with the assigned IP, using dash-separated quads. It is also used for
        identifying the source of logged messages.
        
        `subnet_mask`, `gateway`, and `broadcast_address` are what you'd expect;
        omitting them will limit the client to link-local traffic. They should
        be dotted-quad strings, but may be integers or quadruples.
        
        `domain_name` is used to set the client's search-domain, as a string.
        It is optional.
        
        `domain_name_servers` and `ntp_servers` are also both what you'd expect,
        expressed like ['192.168.0.1', '192.168.0.2'], or as integers or quadruples,
        to a maximum of three items. They are optional, too.
        """
        self._subnet = subnet
        self._serial = serial
        self._lease_time = lease_time
        self._hostname_prefix = hostname_prefix
        self._hostname_pattern = self._hostname_prefix + "-{ip}"
        self._subnet_mask = subnet_mask and IPv4(subnet_mask) or None
        self._gateway = gateway and IPv4(gateway) or None
        self._broadcast_address = broadcast_address and IPv4(broadcast_address) or None
        self._domain_name = domain_name
        self._domain_name_servers = domain_name_servers and [IPv4(i) for i in domain_name_servers] or None
        self._ntp_servers = ntp_servers and [IPv4(i) for i in ntp_servers] or None
        
        #a connection-pool behind the scenes
        self._redis_client = redis.Redis(
            **{k[len('redis_'):]:v for (k, v) in kwargs.items() if k.startswith('redis_')},
        )
        self._lease_key = lease_key
        self._lock = redis.lock.Lock(self._redis_client, self._lease_key, timeout=5, blocking_timeout=0.5, blocking=False)
        
        self._logger = _logger.getChild(self._hostname_prefix)
        
        self._logger.info("Created dynamic provisioning pool '{}'".format(self._hostname_prefix))
        
    def _get_ips_available(self):
        """
        Returns the list of available IPs in least-dirty to most-dirty order.
        
        This method must be called while `self._lock` is held.
        """
        ips_available = self._redis_client.hget(self._lease_key, 'ips_available')
        if ips_available:
            return json.loads(ips_available)
        else:
            return []
        
    def _set_ips_available(self, ips_available):
        """
        Sets the list of available IPs in least-dirty to most-dirty order.
        
        This method must be called while `self._lock` is held.
        """
        self._redis_client.hset(self._lease_key, key='ips_available', value=json.dumps(ips_available, separators=(',', ':')))
        
    def add_ips(self, ips):
        """
        Adds IPs to the allocation pool. Duplicates are filtered out, but order
        is preserved.
        
        `ips` is an iterable, possibly a generator, of IP addresses, like
        ['192.168.0.100', '192.168.0.101'], or integers or quadruples.
        
        To generate it, try calling this method in the following way:
            .add_ips(['192.168.250.' + str(i) for i in range(11, 255)])
        This will add 192.168.250.11-254 with minimal effort. (The last element
        in a range is not generated)
        """
        with self._lock:
            ips_available = self._get_ips_available()
            
            pool = set(ips_available)
            
            new_ips = []
            duplicate_ips = []
            for ip in ips:
                ip = IPv4(ip)
                if ip not in pool:
                    pool.add(ip)
                    new_ips.append(ip)
                else:
                    duplicate_ips.append(ip)
                    
            ips_available.extend(new_ips)
            self._set_ips_available(ips_available)
            
        if duplicate_ips:
            self._logger.warning("Pruned duplicate IPs: {!r}".format(duplicate_ips))
        self._logger.debug("Added IPs to dynamic pool '{}': {}".format(
            self._hostname_prefix,
            new_ips,
        ))
        self._logger.info("Added {} available IPs to dynamic pool '{}'; new total: {}".format(
            len(new_ips),
            self._hostname_prefix,
            len(pool),
        ))
        
    def handle(self, method, packet, mac, client_ip):
        """
        Processes a dynamic request, returning a synthesised lease, if possible.
        
        `method`, `packet`, `mac`, and `client_ip` are all passed through from
        `handleUnknownMAC()` directly.
        
        The value returned is either a Definition or None, depending on success.
        """
        mac = str(mac)
        
        self._logger.info("Dynamic {} from {}{} in pool '{}'".format(
            method,
            mac,
            client_ip and (' for {}'.format(client_ip)) or '',
            self._hostname_prefix,
        ))
        
        if method == 'DISCOVER' or method.startswith('REQUEST:'):
            return self._allocate(mac, client_ip)
        if method == 'RELEASE' or method == 'DECLINE':
            return self._reclaim(mac, client_ip)
        if method == 'INFORM':
            return self._inform(client_ip)
            
        self._logger.info("{} is unknown to the dynamic provisioning engine".format(method))
        return None
        
    def _refresh_leases(self, produce_definitions=False):
        """
        Refreshes IP allocation state, synchronising expirations.
        
        If `produce_definitions` is True, a list of LeaseDefinitions is returned.
        Otherwise, a list of available IPs in least-to-most-dirty order and a
        dictionary of {allocated IP: mac} is returned.
        
        Must be called in a context in which self._lock is held.
        """
        if produce_definitions:
            elements = []
        current_time = time.time()
        
        ip_leases = {}
        active_leases = []
        dead_leases = []
        for (mac, lease) in self._redis_client.hgetall(self._lease_key).items():
            lease_details = json.loads(lease)
            if lease_details['expiration'] <= current_time:
                dead_leases.append((mac, lease_details))
            else:
                active_leases.append((mac, lease_details))
                ip_leases[lease_details['ip']] = mac
                
        #remove leases from Redis
        self._redis_client.hdel(self._lease_key, *[mac for (mac, lease_details) in dead_leases])
        
        #deal with cases where a lease was made by another instance
        #note that a lease manually deleted from Redis will result in an IP disappearing until
        #staticDHCPd is restarted, which is intentional to prevent accidental duplicate assignment
        ips_available = [ip for ip in self._get_ips_available() if ip not in ip_leases]
        if produce_definitions:
            for ip in ips_available:
                elements.append(_LeaseDefinition(ip, None, None, None))
                
        #add released IPs to the end of the list of those available to be allocated so they
        #are at lower risk of duplication in any external caches that may exist
        for (mac, lease_details) in dead_leases:
            ip = lease_details['ip']
            ips_available.append(ip)
            if produce_definitions:
                expiration = lease_details['expiration']
                elements.append(_LeaseDefinition(ip, mac, expiration, expiration - self._lease_time))
            
        self._set_ips_available(ips_available)
        
        if produce_definitions:
            return tuple(sorted(elements))
        else:
            return (ips_available, ip_leases)
            
    def show_leases_csv(self, *args, **kwargs):
        """
        Provides every lease in the system as a CSV document.
        """
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(('ip', 'mac', 'expiration', 'last seen'))
        render_format = '%Y-%m-%d %H:%M:%S'
        with self._lock():
            leases = self._refresh_leases(produce_definitions=True)
        for lease in leases:
            writer.writerow((
                str(lease.ip),
                lease.mac or '',
                lease.expiration and time.strftime(render_format, time.localtime(lease.expiration)) or '',
                lease.last_seen and time.strftime(render_format, time.localtime(lease.last_seen)) or '',
            ))
        output.seek(0)
        return ('text/csv', output.read())
        
    def show_leases_xhtml(self, *args, **kwargs):
        """
        Renders a table containing all leases.
        
        Intended to be used with the web interface.
        """
        try:
            with self._lock:
                leases = self._refresh_leases(produce_definitions=True)
                
            elements = []
            for lease_definition in leases:
                if lease_definition.mac:
                    elements.append("""
                <tr>
                    <td>{ip}</td>
                    <td>{mac}</td>
                    <td>{expiration}</td>
                </tr>""".format(
                        ip=lease_definition.ip,
                        mac=lease_definition.mac,
                        expiration=time.ctime(lease_definition.expiration),
                    ))
                    
            if elements:
                return """
            <table class="element">
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>MAC</th>
                        <th>Expires</th>
                    </tr>
                </thead>
                <tfoot>
                    <tr>
                        <td colspan="3">{count} IPs available</td>
                    </tr>
                </tfoot>
                <tbody>
                    {content}
                </tbody>
            </table>""".format(
                    content='\n'.join(elements),
                    count=len(self._pool),
                )
            else:
                return "No leases yet assigned; {} IPs available".format(len(self._ips_available))
        except Exception as e:
            self._logger.error("Unable to query lease database: {}".format(e))
            return "Unable to query lease database"
            
    def _assign_ip(self, mac, ip, ips_available=None):
        """
        Updates Redis with the IP-to-MAC assignment.
        
        If `ips_available` is not specified, the list is not updated.
        
        Must be called from a context where `self._lock` is held.
        """
        expiration_time = int(time.time() + self._lease_time)
        
        if ips_available is not None:
            self._set_ips_available(ips_available)
        self._redis_client.hset(self._lease_key, key=mac, value=json.dumps({
            'ip': client_ip,
            'expiration': expiration_time,
        }, separators=(',', ':')))
        
        self._logger.info("Granted lease of {} to {} in pool '{}' until {}".format(
            ip,
            mac,
            self._hostname_prefix,
            time.ctime(expiration_time),
        ))
        
    @_dynamic_method
    def _allocate(self, mac, client_ip):
        """
        Associates or retrieves an existing associated IP to `mac`.
        
        Provides an IP for `mac`, whether it's one that's already associated or
        one provisioned on the fly. If `client_ip` is provided, it will be
        pulled from the pool if available; if it conflicts with an allocation,
        it will invalidate the request.
        
        A returned value of None means allocation was not possible.
        """
        with self._lock:
            (ips_available, ip_leases) = self._refresh_leases()
            
            if client_ip:
                associated_mac = ip_leases.get(client_ip)
                if not associated_mac:
                    #Search for the requested IP in the pool
                    for (idx, ip) in enumerate(ips_available):
                        if ip == client_ip:
                            self._assign_ip(mac, ip, ips_available[:idx] + ips_available[idx + 1:])
                            return client_ip
                    else:
                        self._logger.info("Ignoring request for {} from {} in pool '{}': IP is not allocatable".format(
                            client_ip,
                            mac,
                            self._hostname_prefix,
                        ))
                        return None
                elif associated_mac != mac:
                    self._logger.info("Rejected request for {} from {} in pool '{}': does not match associated MAC {}".format(
                        client_ip,
                        mac,
                        self._hostname_prefix,
                        associated_mac,
                    ))
                    return None
                else:
                    #just extend the lease
                    self._assign_ip(mac, client_ip, None)
                    return client_ip
            else:
                if ips_available:
                    #allocate the least-dirty IP
                    self._assign_ip(mac, ips_available[0], ips_available[1:])
                    return ips_available[0]
                else:
                    self._logger.warning("No IP available for assignment to {} in pool '{}'".format(
                        mac,
                        self._hostname_prefix,
                    ))
                    return None
                    
    @_dynamic_method
    def _inform(self, client_ip):
        """
        In the case of an INFORM, no IP is provisioned, so this just returns the
        current `client_ip`.
        
        Returning None will kill the request.
        """
        return client_ip
        
    @_dynamic_method
    def _reclaim(self, mac, client_ip):
        """
        Releases `client_ip` if it is, indeed, bound to `mac`.
        
        Returning None will prevent the request from being acknowledged.
        """
        with self._lock:
            lease_details = self._redis_client.hget(self._lease_key, mac)
            if lease_details:
                lease_details = json.loads(lease_details)
                ip = lease_details['ip']
                
                if ip != client_ip:
                    self._logger.warning("IP assigned to {}, {}, in pool '{}', does not match {}".format(
                        mac,
                        ip,
                        self._hostname_prefix,
                        client_ip,
                    ))
                    return None
                    
                self._redis_client.hdel(self._lease_key, mac)
                
                ips_available = self._get_ips_available()
                ips_available.append(ip)
                self._set_ips_available(ips_available)
                
                self._logger.info("Reclaimed released IP {} from {} in pool '{}'".format(
                    ip,
                    mac,
                    self._hostname_prefix,
                ))
                return ip
            else:
                self._logger.warning("No IP assigned to {} in pool '{}'".format(
                    mac,
                    self._hostname_prefix,
                ))
            return None
            
