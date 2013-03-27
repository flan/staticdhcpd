# -*- encoding: utf-8 -*-
"""
Provides a simple day of defining dynamic allocation pools for more conventional
DHCP behaviour. This module will NOT provide RFC-compliant dynamic management,
but it's close enough to be useful and hasn't yet failed in any use-cases to
which it has been applied.

If you use this module, consider setting `NAK_RENEWALS` in conf.py, to
discourage clients from renewing before their lease-time is up. Alternatively,
you can set 'renewal_time_value' and 'rebinding_time_value' in the packet to
something close to the lease-time itself, which is supported by default.

To use this module, add the following to conf.py's init() function:
    import dynamism
    global _dynamic_pool
    _dynamic_pool = dynamism.DynamicPool(<see its __init__ for parameters>)
    #Add 192.168.250.100-200
    _dynamic_pool.add_ips(['192.168.250.' + str(i) for i in range(100, 201)])
    
    #Expose its allocation table to the web interface
    callbacks.webAddMethod(
     '/yoursite/dynamic-pool/guest/0/show', _dynamic_pool.show_leases,
     hidden=False, module='guest-0', name='show leases',
     display_mode=callbacks.WEB_METHOD_TEMPLATE
    )
    #You could also make it a permanent dashboard fixture:
    #callbacks.webAddDashboard('guest-0', 'leases',_dynamic_pool.show_leases)
    #Add 'ordering=N', where N is a bias value, to change its position
    
And then add the following to conf.py's handleUnknownMAC():
    return _dynamic_pool.handle(method, packet, mac, client_ip)
    
    
You can define as many pools as you'd like, but deciding how to use them is
more advanced than what will be covered here. Checking `giaddr` to determine
the relay-source is probably the most sane method, though.

Note that no validation is performed to ensure that the DHCP request was legal,
just that it was well-formed. Malicious clients cannot compromise the server,
but they can trigger DoS behaviour. Given that there's nothing to gain, however,
this is probably a non-issue.

If you need persistent dynamic allocations, you will need to implement the
functionality yourself (and contribute it, please!), or otherwise set up
another DHCP server, like the ISC's, which is meant for that, and tell
staticDHCPd that it is not authoritative for its network. The intended use-case
for this is giving unknown clients access to a guest subnet so they can be
migrated to a static context. It's usable beyond that, but it is a scope-limited
solution.

(C) Neil Tallim, 2013 <flan@uguu.ca>
"""
import collections
import logging
import threading
import time

from staticdhcpdlib.databases import Definition

from libpydhcpserver.type_rfc import longToList

_logger = logging.getLogger('conf.dynamism')

def _dynamic_method(method):
    """
    Handles locking and response-formatting; you do not need to study this,
    even if you are subclassing DynamicPool: you can just call the parent
    method normally and return its result.
    
    This is just a decorator.
    """
    def wrapped_method(self, *args, **kwargs):
        with self._lock:
            self._cleanup_leases() #Remove stale assignments
            ip = method(self, *args, **kwargs)
            if ip:
                return Definition(
                 ip, self._hostname_pattern % {'ip': ip.replace('.', '-'),},
                 self._gateway, self._subnet_mask, self._broadcast_address,
                 self._domain_name, self._domain_name_servers,
                 self._ntp_servers, self._lease_time,
                 self._subnet, self._serial
                )
            return None
    return wrapped_method
    
class DynamicPool(object):
    def __init__(self,
     subnet, serial, lease_time, hostname_prefix,
     subnet_mask=None, gateway=None, broadcast_address=None,
     domain_name=None, domain_name_servers=None, ntp_servers=None,
     discourage_renewals=True
    ):
        """
        Initialises a new pool, containing no IPs. Call `add_ips()` to add some.
        
        `subnet` is any string you would like to use, like 'guest', and `serial`
        is its complement, an integer that lets you re-use the same subnet-name;
        guest network 0, 1, 2... What you use is up to you.
        
        `lease_time` is the number of seconds for which a lease will be offered.
        
        `hostname_prefix` is the leading part of the hostname to offer to
        clients; it should be something simple like 'guest-0'; it is completed
        with the assigned IP, using dash-separated quads. It is also used for
        identifying the source of logged messages.
        
        `subnet_mask`, `gateway`, and `broadcast_address` are what you'd expect;
        omitting them will limit the client to link-local traffic. They're all
        dotted-quad strings.
        
        `domain_name` is used to set the client's search-domain, as a string.
        It is optional.
        
        `domain_name_servers` and `ntp_servers` are also both what you'd expect,
        expressed like ['192.168.0.1', '192.168.0.2'], to a maximum of three
        items. They are optional, too.
        
        `discourage_renewals` will modify packets to tell the client to hold off
        on renewing until the lease is up. Not all clients will respect this. It
        is enabled by default.
        """
        self._subnet = subnet
        self._serial = serial
        self._lease_time = lease_time
        self._hostname_prefix = hostname_prefix
        self._hostname_pattern = self._hostname_prefix + "-%(ip)s"
        self._subnet_mask = subnet_mask
        self._gateway = gateway
        self._broadcast_address = broadcast_address
        self._domain_name = domain_name
        self._domain_name_servers = domain_name_servers and ','.join(domain_name_servers) or None
        self._ntp_servers = ntp_servers and ','.join(ntp_servers) or None
        self._discourage_renewals = discourage_renewals
        
        self._logger = _logger.getChild(self._hostname_prefix)
        self._pool = collections.deque()
        self._map = {}
        self._lock = threading.Lock()
        
        self._logger.info("Created dynamic provisioning pool '%(name)s'" % {'name': self._hostname_prefix})
        
    def add_ips(self, ips):
        """
        Adds IPs to the allocation pool. Duplicates are filtered out, but order
        is preserved.
        
        `ips` is a sequence of IP addresses, like
        ['192.168.0.100', '192.168.0.101'].
        
        To generate it, try calling this method in the following way:
            .add_ips(['192.168.250.' + str(i) for i in range(11, 255)])
        This will add 192.168.250.11-254 with minimal effort. (The last element
        in a range is not generated)
        """
        with self._lock:
            ips = [ip for ip in ips if ip not in self._pool]
            self._pool.extend(ips)
        self._logger.debug("Added IPs to dynamic pool '%(name)s': %(ips)s" % {
         'ips': str(ips),
         'name': self._hostname_prefix,
        })
        self._logger.info("Added %(count)i IPs to dynamic pool '%(name)s'; new total: %(total)i" % {
         'count': len(ips),
         'total': len(self._pool),
         'name': self._hostname_prefix,
        })
        
    def handle(self, method, packet, mac, client_ip):
        """
        Processes a dynamic request, returning a synthesised lease, if possible.
        
        `method`, `packet`, `mac`, and `client_ip` are all passed through from
        `handleUnknownMAC()` directly.
        
        The value returned is either a Definition or None, depending on success.
        """
        client_ip = client_ip and '.'.join(map(str, client_ip))
        
        self._logger.info("Dynamic %(method)s from %(mac)s%(ip)s in pool '%(name)s'" % {
         'method': method,
         'mac': mac,
         'ip': client_ip and (' for %(ip)s' % {'ip': client_ip,}) or '',
         'name': self._hostname_prefix,
        })
        
        if method == 'DISCOVER' or method.startswith('REQUEST:'):
            definition = self._allocate(mac, client_ip)
            if definition and self._discourage_renewals:
                self._logger.debug("Setting T1 and T2 to match lease-time")
                packet.setOption('renewal_time_value', longToList(definition.lease_time))
                packet.setOption('rebinding_time_value', longToList(definition.lease_time))
            return definition
        if method == 'RELEASE' or method == 'DECLINE':
            return self._reclaim(mac, client_ip)
        if method == 'INFORM':
            return self._inform(client_ip)
            
        self._logger.info("%(method)s is unknown to the dynamic provisioning engine" % {
         'method': method,
        })
        return None
        
    def show_leases(self, *args, **kwargs):
        """
        Renders a table containing all leases.
        
        Intended to be used with the web interface.
        """
        with self._lock:
            if not self._map:
                return "No leases yet assigned; %(count)i IPs available" % {'count': len(self._pool)}
                
            elements = []
            for ((expiration, ip), mac) in sorted((v, k) for (k, v) in self._map.iteritems()):
                elements.append("""<tr>
                    <td>%(ip)s</td>
                    <td>%(mac)s</td>
                    <td>%(expiration)s</td>
                </tr>""" % {
                 'ip': ip,
                 'mac': mac,
                 'expiration': time.ctime(expiration),
                })
            elements.append('<tr><td colspan="3" style="text-align: center;">%(count)i IPs available</td></tr>' % {
             'count': len(self._pool),
            })
            return """<table class="element">
                <thead>
                    <th>IP</th>
                    <th>MAC</th>
                    <th>Expires</th>
                </thead>
                <tbody>
                    %(content)s
                </tbody>
            </table>""" % {
             'content': '\n'.join(elements),
            }
            
    def _cleanup_leases(self):
        """
        Reclaims IPs for which leases have lapsed.
        
        Must be called from a context in which the lock is held.
        """
        current_time = time.time()
        dead_records = []
        for (mac, (expiration, ip)) in self._map.iteritems():
            if current_time - expiration > self._lease_time: #Kill it
                dead_records.append((mac, ip))
                
        for (mac, ip) in dead_records:
            del self._map[mac]
            self._pool.append(ip)
            self._logger.debug("Reclaimed expired IP %(ip)s from %(mac)s in pool '%(name)s'" % {
             'ip': ip,
             'mac': mac,
             'name': self._hostname_prefix,
            })
            
    def _drop_lease(self, mac):
        """
        Frees the IP bound to `mac`, if any. The IP is returned.
        
        Must be called from a context in which the lock is held.
        """
        match = self._map.get(mac)
        if match: #Drop the lease and reclaim the IP
            ip = match[1]
            del self._map[mac]
            self._pool.append(ip)
            self._logger.info("Reclaimed released IP %(ip)s from %(mac)s in pool '%(name)s'" % {
             'ip': ip,
             'mac': mac,
             'name': self._hostname_prefix,
            })
            return ip
        return None
        
    def _get_lease(self, mac, client_ip):
        """
        Provides an IP for `mac`, whether it's one that's already associated or
        one provisioned on the fly. If `client_ip` is provided, it will be
        pulled from the pool if available; if it conflicts with an allocation,
        it will invalidate the request.
        
        Must be called from a context in which the lock is held.
        """
        match = self._map.get(mac)
        if match: 
            ip = match[1]
            if client_ip and ip != client_ip:
                self._logger.info("Rejected request for %(ip)s from %(mac)s in pool '%(name)s': does not match allocation of %(aip)s" % {
                 'ip': client_ip,
                 'aip': ip,
                 'mac': mac,
                 'name': self._hostname_prefix,
                })
                return None
                
            match[0] = time.time() + self._lease_time
            self._logger.info("Extended lease of %(ip)s to %(mac)s in pool '%(name)s' until %(time)s" % {
             'ip': ip,
             'mac': mac,
             'time': time.ctime(match[0]),
             'name': self._hostname_prefix,
            })
            return ip
        else:
            if self._pool:
                if client_ip: #Search for the requested IP in the pool
                    for (i, ip) in enumerate(self._pool):
                        if ip == client_ip:
                            del self._pool[i]
                            break
                    else:
                        ip = self._pool.popleft()
                else:
                    ip = self._pool.popleft()
                    
                expiration = time.time() + self._lease_time
                self._map[mac] = [expiration, ip]
                self._logger.info("Bound %(ip)s to %(mac)s in pool '%(name)s' until %(time)s" % {
                 'ip': ip,
                 'mac': mac,
                 'time': time.ctime(expiration),
                 'name': self._hostname_prefix,
                })
                return ip
            return None
            
    def _query_lease(self, mac):
        """
        Provides the IP associated with `mac`, if any.
        
        Must be called from a context in which the lock is held.
        """
        match = self._map.get(mac)
        if match:
            return match[1]
        return None
        
    @_dynamic_method
    def _allocate(self, mac):
        """
        Associates or retrieves an existing associated IP to `mac`.
        
        A returned value of None means nothing was available.
        """
        ip = self._get_lease(mac)
        if not ip:
            self._logger.error("No IP available for assignment to %(mac)s in pool '%(name)s'" % {
             'mac': mac,
             'name': self._hostname_prefix,
            })
        return ip
        
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
        ip = self._query_lease(mac)
        if not ip:
            self._logger.warn("No IP assigned to %(mac)s in pool '%(name)s'" % {
             'mac': mac,
             'name': self._hostname_prefix,
            })
            return None
        elif ip != client_ip:
            self._logger.warn("IP assigned to %(mac)s, %(aip)s, in pool '%(name)s', does not match %(ip)s" % {
             'aip': ip,
             'ip': client_ip,
             'mac': mac,
             'name': self._hostname_prefix,
            })
            return None
        return self._drop_lease(mac)
        