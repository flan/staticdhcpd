"""
Import this module from conf.py and call `provisionDynamic(mac)` to get dynamic
allocations, good for use in a single-DHCP-server environment. Do be aware that
no validation is performed to ensure that the DHCP request was legal, just that
it was well-formed. Malicious clients cannot compromise the server, but they
can trigger DoS behaviour. Given that there's nothing to gain, however, this is
probably a non-issue.

Please make changes to this module before using it in your environment. The
default settings are almost certainly good for nobody.

Consider setting 'renewal_time_value' and 'rebinding_time_value' to some number
very close to, if not equal to, your lease-time, to avoid having clients extend
leases longer than necessary; if you want a more persistent dynamic solution,
you should be using the ISC server. The best use-case for this is giving
unknown clients access to a guest subnet so they can be migrated to a static
context.

You can identify dynamic requests by using a unique subnet/serial pair and
checking for it in loadDHCPPacket().
"""
import collections
import threading
import time

import src.logging

#Configure these variables as needed
###############################################################################
LEASE_TIME = 300 #seconds
SUBNET = 'guest'
SERIAL = 0

#Add any elements you want to the list, as dotted-quad-notation IPv4 addresses
_IPS = set([])
#Use patterns like this to add blocks of IPs; this covers .11-.254
_IPS.add(['192.168.250.' + str(i) for i in xrange(11, 255)])

_SUBNET_MASK = '255.255.255.0'
_GATEWAY = '192.168.250.1'
_BROADCAST_ADDRESS = '192.168.250.255'
_DOMAIN_NAME = 'guestnet.example.org' #None to not have a default search-domain
_DOMAIN_NAME_SERVERS = ('192.168.250.5', '192.168.250.6', '192.168.250.7') #Limit: 3
_NTP_SERVERS = ('192.168.250.2', '192.168.250.3', '192.168.250.4')#Limit: 3
###############################################################################
#Don't touch anything else, unless you want to (it's your network, after all)

_IPS = collections.deque(sorted(_IPS)) #Redefine the set of IPs as an initially-sorted deque for sanity
_IPS_LOCK = threading.Lock()
_DYNAMIC_MAP = {}
_DYNAMIC_MAP_LOCK = threading.Lock()

#Finalise common strings
_DOMAIN_NAME_SERVERS = ','.join(_DOMAIN_NAME_SERVERS)
_NTP_SERVERS = ','.join(_NTP_SERVERS)
_HOSTNAME_PATTERN = SUBNET + '-' + str(SERIAL) + '-'


def _cleanupLeases():
	current_time = time.time()
	dead_records = []
	with _DYNAMIC_MAP_LOCK:
		for (mac, (expiration, ip)) in _DYNAMIC_MAP.items():
			if current_time - expiration > LEASE_TIME: #Kill it
				dead_records.append(mac)
				with _IPS_LOCK: #Put the IP back into the pool
					_IPS.append(ip)
					
		for mac in dead_records:
			del _DYNAMIC_MAP[mac]
			
def _getLease(mac):
	ip = None
	with _DYNAMIC_MAP_LOCK:
		match = _DYNAMIC_MAP.get(mac)
		if match: #Renew the lease and take the IP
			match[0] = time.time() + LEASE_TIME
			ip = match[1]
			
			src.logging.writeLog("Extended lease of '%(ip)s' to '%(mac)s' until '%(time).1f'" % {
			 'ip': ip,
			 'mac': mac,
			 'time': match[0],
			})
		else:
			with _IPS_LOCK:
				if _IPS:
					ip = _IPS.popleft()
					
			if ip:
				expiration = time.time() + LEASE_TIME
				_DYNAMIC_MAP[mac] = [expiration, ip]
				src.logging.writeLog("Bound '%(ip)s' to '%(mac)s' until '%(time).1f'" % {
				 'ip': ip,
				 'mac': mac,
				 'time': expiration,
				})
	return ip
	
def provisionDynamic(mac):
	"""
	If you need to reject a MAC, return None instead of the usual value.
	"""
	src.logging.writeLog("Processing dynamic provisioning request from '%(mac)s'..." % {
	 'mac': mac,
	})
	
	_cleanupLeases() #Remove stale assignments
	ip = _getLease(mac)
	if not ip: #No IP available; fail
		src.logging.writeLog("No IP available for assignment to '%(mac)s'" % {
		 'mac': mac,
		})
		return None
		
	return (
	 ip, _HOSTNAME_PATTERN + ip.replace('.', '-'),
	 _GATEWAY, _SUBNET_MASK, _BROADCAST_ADDRESS,
	 _DOMAIN_NAME, _DOMAIN_NAME_SERVERS,
	 NTP_SERVERS, LEASE_TIME,
	 SUBNET, SERIAL
	)
	