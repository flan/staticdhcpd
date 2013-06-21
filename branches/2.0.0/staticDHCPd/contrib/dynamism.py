# -*- encoding: utf-8 -*-
"""
Provides a simple way of defining dynamic allocation pools for more conventional
DHCP behaviour. This module will NOT provide RFC-compliant dynamic management,
but it's close enough to be useful and hasn't yet failed in any use-cases to
which it has been applied.

If you use this module, consider setting `NAK_RENEWALS` in conf.py, to
discourage clients from renewing before their lease-time is up. Alternatively,
leave discourage_renewals=True when setting up a pool to suggest that clients
avoid communicating wiht the server until their lease is almost up, rather than
at 50% and 75%, which is spec-default.

To use this module, add the following to conf.py's init() function:
    import dynamism
    global _dynamic_pool
    _dynamic_pool = dynamism.DynamicPool(<see its __init__ for parameters>)
    #Add 192.168.250.100-200
    _dynamic_pool.add_ips(['192.168.250.' + str(i) for i in range(100, 201)])
    
    #Expose its allocation table to the web interface
    callbacks.webAddMethod(
     '/yoursite/dynamic-pool/guest/0/leases', _dynamic_pool.show_leases_xhtml,
     hidden=False, module='guest-0', name='show leases',
     display_mode=callbacks.WEB_METHOD_TEMPLATE
    )
    #You could also make it a permanent dashboard fixture:
    #callbacks.webAddDashboard('guest-0', 'leases', _dynamic_pool.show_leases_xhtml)
    #Add 'ordering=N', where N is a bias value, to change its position
    
    #And a CSV form, too, in case any automated processors need the data
    callbacks.webAddMethod(
     '/yoursite/dynamic-pool/guest/0/leases.csv', _dynamic_pool.show_leases_csv,
     hidden=False, module='guest-0', name='get leases (csv)',
     display_mode=callbacks.WEB_METHOD_RAW
    )
    
And then add the following to conf.py's handleUnknownMAC():
    return _dynamic_pool.handle(method, packet, mac, client_ip)
    
    
You can define as many pools as you'd like, but deciding how to use them is
more advanced than what will be covered here. Checking `giaddr` to determine
the relay-source is probably the most sane method, though.

Note that no validation is performed to ensure that the DHCP request was legal,
just that it was well-formed. Malicious clients cannot compromise the server,
but they can trigger DoS behaviour. Given that there's nothing to gain, however,
this is probably a non-issue.

While this module will, if scapy is available, provide sufficient coherency to
run multiple servers in an environment (provided you have decent proxy-ARP
support if using relays), or to run a single unstable server, if you need truly
persistent dynamic allocations, you will need to implement the
functionality yourself (and contribute it, please!), or otherwise set up
another DHCP server, like the ISC's, which is meant for that, and tell
staticDHCPd that it is not authoritative for its network. The intended use-case
for this is giving unknown clients access to a guest subnet so they can be
migrated to a static context. It's usable well beyond that, but it is a
scope-limited design.

Like staticDHCPd, this module under the GNU General Public License v3
(C) Neil Tallim, 2013 <flan@uguu.ca>
"""
import collections
import logging
import threading
import time

from staticdhcpdlib.databases.generic import Definition

from libpydhcpserver.dhcp_types.rfc import longToList
from libpydhcpserver.dhcp_types.ipv4 import IPv4

_logger = logging.getLogger('contrib.dynamism')

_logger.info("Attempting to import scapy; scapy-specific logging output may follow")
try:
    import scapy.route
    from scapy.layer.l2 import arping
except ImportError:
    _logger.warn("scapy is unavailable; addresses added to pools cannot be automatically ARPed")
    arping = None
else:
    _logger.info("scapy imported successfully; automatic ARPing is available")
    
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
        omitting them will limit the client to link-local traffic. They should
        be dotted-quad strings, but may be integers or quadruples.
        
        `domain_name` is used to set the client's search-domain, as a string.
        It is optional.
        
        `domain_name_servers` and `ntp_servers` are also both what you'd expect,
        expressed like ['192.168.0.1', '192.168.0.2'], or as integers or quadruples,
        to a maximum of three items. They are optional, too.
        
        `discourage_renewals` will modify packets to tell the client to hold off
        on renewing until the lease is up. Not all clients will respect this. It
        is enabled by default.
        """
        self._subnet = subnet
        self._serial = serial
        self._lease_time = lease_time
        self._hostname_prefix = hostname_prefix
        self._hostname_pattern = self._hostname_prefix + "-%(ip)s"
        self._subnet_mask = subnet_mask and tuple(IPv4(subnet_mask)) or None
        self._gateway = gateway and tuple(IPv4(gateway)) or None
        self._broadcast_address = broadcast_address and tuple(IPv4(broadcast_address)) or None
        self._domain_name = domain_name
        self._domain_name_servers = domain_name_servers or None
        self._ntp_servers = ntp_servers or None
        self._discourage_renewals = discourage_renewals
        
        self._logger = _logger.getChild(self._hostname_prefix)
        self._pool = collections.deque()
        self._map = {}
        self._lock = threading.Lock()
        
        self._logger.info("Created dynamic provisioning pool '%(name)s'" % {'name': self._hostname_prefix})
        
    def add_ips(self, ips, arp_addresses=True, arp_timeout=1.0):
        """
        Adds IPs to the allocation pool. Duplicates are filtered out, but order
        is preserved.
        
        `ips` is a sequence of IP addresses, like
        ['192.168.0.100', '192.168.0.101'], or integers or quadruples.
        
        To generate it, try calling this method in the following way:
            .add_ips(['192.168.250.' + str(i) for i in range(11, 255)])
        This will add 192.168.250.11-254 with minimal effort. (The last element
        in a range is not generated)
        
        `arp_addresses` will, if True, the default, try to use scapy, if
        installed, to ARP every supplied address, building a lease-map for
        already-allocated IPs, which should minimise unnecessary DECLINEs.
        
        `arp_timeout` is the number of seconds to wait for a addresses to
        respond.
        """
        ips = dict((ip, IPv4(ip)) for ip in ips)
        with self._lock:
            #Filter out duplicates
            allocated_ips = set(ip for (_, ip) in self._map.itervalues())
            duplicate_ips = []
            for (ip, ip_obj) in ips.iteritems():
                if ip_obj in self._pool or ip_obj in allocated_ips:
                    duplicate_ips.append(ip)
            if duplicate_ips:
                for ip in duplicate_ips:
                    del ips[ip]
                self._logger.warn("Pruned duplicate IPs: %(ips)r" % {'ips': duplicate_ips,})
                
            #Try to ARP addresses
            if arp_addresses and arping:
                expiration = time.time() + self._lease_time
                mapped_ips = 0
                self._logger.info("Beginning ARP-lookup for %(count)i IPs in pool '%(name)s', with timeout=%(timeout).3fs" % {
                 'count': len(ips),
                 'timeout': arp_timeout,
                 'name': self._hostname_prefix,
                })
                (answered, unanswered) = arping(ips.keys(), verbose=0, timeout=arp_timeout)
                for answer in answered:
                    try:
                        ip = answer[0].payload.fields['pdst']
                        mac = answer[1].fields['src'].lower()
                        ip_obj = ips.pop(ip)
                    except Exception, e:
                        self._logger.debug("Unable to use ARP-discovered binding %(binding)r: %(error)s" % {
                         'binding': answer,
                         'error': str(e),
                        })
                    else:
                        mapped_ips += 1
                        self._map[mac] = [expiration, ip_obj]
                        self._logger.info("ARP-discovered %(ip)s bound to %(mac)s in pool '%(name)s'; providing lease until %(time)s" % {
                         'ip': ip_obj,
                         'mac': mac,
                         'time': time.ctime(expiration),
                         'name': self._hostname_prefix,
                        })
                self._logger.info("%(count)i IPs automatically bound in pool '%(name)s'" % {
                 'count': mapped_ips,
                 'name': self._hostname_prefix,
                })
            self._pool.extend(ips.itervalues())
            total = len(self._pool) + len(self._map)
        self._logger.debug("Added IPs to dynamic pool '%(name)s': %(ips)s" % {
         'ips': str(list(sorted(ips.values()))),
         'name': self._hostname_prefix,
        })
        self._logger.info("Added %(count)i available IPs to dynamic pool '%(name)s'; new total: %(total)i" % {
         'count': len(ips),
         'total': total,
         'name': self._hostname_prefix,
        })
        
    def handle(self, method, packet, mac, client_ip):
        """
        Processes a dynamic request, returning a synthesised lease, if possible.
        
        `method`, `packet`, `mac`, and `client_ip` are all passed through from
        `handleUnknownMAC()` directly.
        
        The value returned is either a Definition or None, depending on success.
        """
        mac = str(mac)
        
        self._logger.info("Dynamic %(method)s from %(mac)s%(ip)s in pool '%(name)s'" % {
         'method': method,
         'mac': mac,
         'ip': client_ip and (' for %(ip)s' % {'ip': client_ip,}) or '',
         'name': self._hostname_prefix,
        })
        
        if method == 'DISCOVER' or method.startswith('REQUEST:'):
            definition = self._allocate(mac, client_ip)
            if definition and self._discourage_renewals:
                target_time = int(definition.lease_time * 0.975)
                self._logger.debug("Setting T1 and T2 to 97.5%% of lease-time=%(lease)i: %(target)i seconds" % {
                 'lease': definition.lease_time,
                 'target': target_time,
                })
                packet.setOption('renewal_time_value', longToList(target_time))
                packet.setOption('rebinding_time_value', longToList(target_time))
            return definition
        if method == 'RELEASE' or method == 'DECLINE':
            return self._reclaim(mac, client_ip)
        if method == 'INFORM':
            return self._inform(client_ip)
            
        self._logger.info("%(method)s is unknown to the dynamic provisioning engine" % {
         'method': method,
        })
        return None
        
    def get_leases(self, *args, **kwargs):
        """
        Provides every lease known to the system, as a tuple of LeaseDefinition
        objects.
        """
        elements = []
        with self._lock:
            for (mac, (expiration, ip)) in self._map.iteritems():
                elements.append(_LeaseDefinition(ip, mac, expiration, expiration - self._lease_time))
            for ip in self._pool:
                elements.append(_LeaseDefinition(ip, None, None, None))
        return tuple(sorted(elements))
        
    def show_leases_csv(self, *args, **kwargs):
        """
        Provides every lease in the system, as a CSV document.
        """
        import csv
        import StringIO
        
        output = StringIO.StringIO()
        writer = csv.writer(output)
        writer.writerow(('ip', 'mac', 'expiration', 'last seen'))
        render_format = '%Y-%m-%d %H:%M:%S'
        for lease in self.get_leases():
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
        with self._lock:
            if not self._map:
                return "No leases yet assigned; %(count)i IPs available" % {'count': len(self._pool)}
                
            elements = []
            for (mac, (expiration, ip)) in sorted(self._map.iteritems(), key=(lambda element: element[1])):
                elements.append("""
                <tr>
                    <td>%(ip)s</td>
                    <td>%(mac)s</td>
                    <td>%(expiration)s</td>
                </tr>""" % {
                 'ip': ip,
                 'mac': mac,
                 'expiration': time.ctime(expiration),
                })
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
                        <td colspan="3">%(count)i IPs available</td>
                    </tr>
                </tfoot>
                <tbody>
                    %(content)s
                </tbody>
            </table>""" % {
             'content': '\n'.join(elements),
             'count': len(self._pool),
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
    def _allocate(self, mac, client_ip):
        """
        Associates or retrieves an existing associated IP to `mac`.
        
        A returned value of None means nothing was available.
        """
        ip = self._get_lease(mac, client_ip)
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
        
