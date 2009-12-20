# -*- encoding: utf-8 -*-
"""
staticDHCPd module: src.dhcp

Purpose
=======
 Provides the DHCPd side of a staticDHCPd server.
 
Legal
=====
 This file is part of staticDHCPd.
 staticDHCPd is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program. If not, see <http://www.gnu.org/licenses/>.
 
 (C) Neil Tallim, 2009
"""
import select
import threading
import time

import conf

import src.logging
import src.sql

import pydhcplib.dhcp_network
import pydhcplib.dhcp_packet
import pydhcplib.type_hwmac
import pydhcplib.type_strlist

def _logInvalidValue(name, value, subnet, serial):
	src.logging.writeLog("Invalid value for %(subnet)s:%(serial)i:%(name)s: %(value)s" % {
	 'subnet': subnet,
	 'serial': serial,
	 'name': name,
	 'value': value,
	})
	
def ipToQuad(ip):
	return [int(i) for i in ip.split('.')]
	
def ipsToQuads(ips):
	quads = []
	for ip in ips.split(','):
		quads += [int(i) for i in ip.strip().split('.')]
	return quads
	
def intToDouble(i):
	"""
	A convenience function that converts an int into a pydhcplib-compatible
	double.
	
	@type i: int
	@param i: The long value to convert.
	
	@rtype: list
	@return: The converted double.
	"""
	return [(i / 256) % 256, i % 256]
	
def longToQuad(l):
	"""
	A convenience function that converts a long into a pydhcplib-compatible
	quad.
	
	@type l: int
	@param l: The long value to convert.
	
	@rtype: list
	@return: The converted quad.
	"""
	q = [l % 256]
	l /= 256
	q.insert(0, l % 256)
	l /= 256
	q.insert(0, l % 256)
	l /= 256
	q.insert(0, l % 256)
	return q
	
def strToStrList(s):
	return pydhcplib.type_strlist.strlist(str(s)).list()
	
class _DHCPServer(pydhcplib.dhcp_network.DhcpNetwork):
	"""
	The handler that responds to all received DHCP requests.
	"""
	_server_address = None #: The IP of the interface from which DHCP responses should be sent.
	_server_port = None #: The port on which DHCP requests are expected to arrive.
	_client_port = None #: The port on which clients expect DHCP responses to be sent.
	
	_sql_broker = None #: The SQL broker to be used when handling MAC lookups.
	
	_stats_lock = None #: A lock used to ensure synchronous access to performance statistics.
	_packets_processed = 0 #: The number of packets processed since the last polling interval.
	_packets_discarded = 0 #: The number of packets discarded since the last polling interval.
	_time_taken = 0.0 #: The amount of time taken since the last polling interval.
	_dhcp_assignments = None #: The MACs and the number of DHCP "leases" granted to each since the last polling interval.
	_ignored_addresses = None #: A list of all MACs currently ignored, plus the time remaining until requests will be honoured again.
	
	def __init__(self, server_address, server_port, client_port):
		"""
		Constructs the DHCP handler.
		
		@type server_address: basestring
		@param server_address: The IP of the interface from which DHCP responses
			are to be sent.
		@type server_port: int
		@param server_port: The port on which DHCP requests are expected to
			arrive.
		@type client_port: int
		@param client_port: The port on which clients expect DHCP responses to be
			sent.
		
		@raise Exception: If a problem occurs while initializing the sockets
			required to process DHCP messages.
		"""
		self._stats_lock = threading.Lock()
		self._dhcp_assignments = {}
		self._ignored_addresses = []
		
		self._server_address = server_address
		self._server_port = server_port
		self._client_port = client_port
		
		pydhcplib.dhcp_network.DhcpNetwork.__init__(
		 self, server_address, server_port, client_port
		)
		
		self.CreateSocket()
		self.BindToAddress()
		
		self._sql_broker = src.sql.SQL_BROKER()
		
	def EvaluateRelay(self, packet):
		"""
		Determines whether the received packet belongs to a relayed request or
		not and decides whether it should be allowed based on policy.
		
		@type packet: L{pydhcplib.dhcp_packet.DhcpPacket}
		@param packet: The packet to be evaluated.
		"""
		giaddr = packet.GetGiaddr()
		if not giaddr == [0, 0, 0, 0]: #Relayed request.
			if not conf.ALLOW_DHCP_RELAYS: #Ignore it.
				return False
			elif conf.ALLOWED_DHCP_RELAYS and not '.'.join(map(str, giaddr)) in conf.ALLOWED_DHCP_RELAYS:
				src.logging.writeLog('Relayed request from unauthorized relay %(ip)s ignored' % {
				 'ip': '.'.join(map(str, giaddr)),
				})
				return False
		elif not conf.ALLOW_LOCAL_DHCP: #Local request, but denied.
			return False
		return True
		
	def GetNextDhcpPacket(self):
		"""
		Listens for a DHCP packet and initiates processing upon receipt.
		"""
		if pydhcplib.dhcp_network.DhcpNetwork.GetNextDhcpPacket(self):
			self._stats_lock.acquire()
			self._packets_processed += 1
			self._stats_lock.release()
			
	def GetStats(self):
		"""
		Returns the performance statistics of all operations performed since the
		last polling event, resets all counters, and updates the time left before
		ignored MACs' requests will be processed again.
		"""
		self._stats_lock.acquire()
		try:
			for i in range(len(self._ignored_addresses)):
				self._ignored_addresses[i][1] -= conf.POLLING_INTERVAL
			self._ignored_addresses = [address for address in self._ignored_addresses if address[1] > 0]
			
			stats = (self._packets_processed, self._packets_discarded, self._time_taken, len(self._ignored_addresses))
			
			self._packets_processed = 0
			self._packets_discarded = 0
			self._time_taken = 0.0
			if conf.ENABLE_SUSPEND:
				self._dhcp_assignments = {}
				
			return stats
		finally:
			self._stats_lock.release()
			
	def HandleDhcpDiscover(self, packet, source_address):
		"""
		Evaluates a DHCPDISCOVER request from a client and determines whether a
		DHCPOFFER should be sent.
		
		The logic here is to make sure the MAC isn't ignored or acting
		maliciously, then check the database to see whether it has an assigned
		IP. If it does, that IP is offered, along with all relevant options; if
		not, the MAC is ignored to mitigate spam from follow-up DHCPDISCOVERS.
		
		@type packet: L{pydhcplib.dhcp_packet.DhcpPacket}
		@param packet: The DHCPDISCOVER to be evaluated.
		@type source_address: tuple
		@param source_address: The address (host, port) from which the request
			was received.
		"""
		if not self.EvaluateRelay(packet):
			return
			
		start_time = time.time()
		mac = pydhcplib.type_hwmac.hwmac(packet.GetHardwareAddress()).str()
		if not [None for (ignored_mac, timeout) in self._ignored_addresses if mac == ignored_mac]:
			if not self.LogDHCPAccess(mac):
				self.LogDiscardedPacket()
				return
				
			src.logging.writeLog('DHCPDISCOVER received from %(mac)s' % {
			 'mac': mac,
			})
			
			try:
				result = self._sql_broker.lookupMAC(mac)
				if result:
					offer = pydhcplib.dhcp_packet.DhcpPacket()
					offer.CreateDhcpOfferPacketFrom(packet)
					
					offer.SetOption('server_identifier', ipToQuad(self._server_address))
					self.LoadDHCPPacket(offer, result)
					giaddr = packet.GetGiaddr()
					if not giaddr or giaddr == [0,0,0,0]:
						giaddr = None
					else:
						giaddr = tuple(giaddr)
					if conf.loadDHCPPacket(
					 offer,
					 mac, tuple(ipToQuad(result[0])), giaddr,
					 result[8], result[9]
					):
						self.SendDhcpPacket(offer, source_address, 'OFFER', mac, result[0])
					else:
						src.logging.writeLog('Ignoring %(mac)s per loadDHCPPacket()' % {
						 'mac': mac,
						})
						self.LogDiscardedPacket()
				else:
					src.logging.writeLog('%(mac)s unknown; ignoring for %(time)i seconds' % {
					 'mac': mac,
					 'time': conf.UNAUTHORIZED_CLIENT_TIMEOUT,
					})
					self._stats_lock.acquire()
					self._ignored_addresses.append([mac, conf.UNAUTHORIZED_CLIENT_TIMEOUT])
					self._stats_lock.release()
			except Exception, e:
				src.logging.sendErrorReport('Unable to respond to %(mac)s' % {'mac': mac,}, e)
		else:
			self.LogDiscardedPacket()
		self.LogTimeTaken(time.time() - start_time)
		
	def HandleDhcpRequest(self, packet, source_address):
		"""
		Evaluates a DHCPREQUEST request from a client and determines whether a
		DHCPACK should be sent.
		
		The logic here is to make sure the MAC isn't ignored or acting
		maliciously, then check the database to see whether it has an assigned
		IP. If it does, and the IP it thinks it has a right to matches this IP,
		then an ACK is sent, along with all relevant options; if	not, a DHCPNAK
		is sent to inform the client that it is not allowed to use the requested
		IP, forcing it to DISCOVER a new one.
		
		If policy forbids RENEW and REBIND operations, perhaps to prepare for a
		new configuration reollout, all such requests are NAKed immediately.
		
		@type packet: L{pydhcplib.dhcp_packet.DhcpPacket}
		@param packet: The DHCPREQUEST to be evaluated.
		@type source_address: tuple
		@param source_address: The address (host, port) from which the request
			was received.
		"""
		if not self.EvaluateRelay(packet):
			return
			
		start_time = time.time()
		mac = pydhcplib.type_hwmac.hwmac(packet.GetHardwareAddress()).str()
		if not [None for (ignored_mac, timeout) in self._ignored_addresses if mac == ignored_mac]:
			if not self.LogDHCPAccess(mac):
				self.LogDiscardedPacket()
				return
				
			ip = packet.GetOption("request_ip_address")
			sid = packet.GetOption("server_identifier")
			ciaddr = packet.GetOption("ciaddr")
			giaddr = packet.GetGiaddr()
			s_ip = '.'.join(map(str, ip))
			s_sid = '.'.join(map(str, sid))
			s_ciaddr = '.'.join(map(str, ciaddr))
			
			if not ip or ip == [0,0,0,0]:
				ip = None
			if not sid or sid == [0,0,0,0]:
				sid = None
			if not ciaddr or ciaddr == [0,0,0,0]:
				ciaddr = None
			if not giaddr or giaddr == [0,0,0,0]:
				giaddr = None
			else:
				giaddr = tuple(giaddr)
				
			if sid and not ciaddr: #SELECTING
				src.logging.writeLog('DHCPREQUEST:SELECTING(%(ip)s) received from %(mac)s' % {
				 'ip': s_sid,
				 'mac': mac,
				})
				if s_sid == self._server_address: #Chosen!
					try:
						result = self._sql_broker.lookupMAC(mac)
						if result and (not ip or result[0] == s_ip):
							packet.TransformToDhcpAckPacket()
							self.LoadDHCPPacket(packet, result)
							if conf.loadDHCPPacket(
							 packet,
							 mac, tuple(ipToQuad(result[0])), giaddr,
							 result[8], result[9]
							):
								self.SendDhcpPacket(packet, source_address, 'ACK', mac, s_ip)
							else:
								src.logging.writeLog('Ignoring %(mac)s per loadDHCPPacket()' % {
								 'mac': mac,
								})
								self.LogDiscardedPacket()
						else:
							packet.TransformToDhcpNackPacket()
							self.SendDhcpPacket(packet, source_address, 'NAK', mac, 'NO-MATCH')
					except Exception, e:
						src.logging.sendErrorReport('Unable to respond to %(mac)s' % {'mac': mac,}, e)
			elif not sid and not ciaddr and ip: #INIT-REBOOT
				src.logging.writeLog('DHCPREQUEST:INIT-REBOOT received from %(mac)s' % {
				 'mac': mac,
				})
				try:
					result = self._sql_broker.lookupMAC(mac)
					if result and result[0] == s_ip:
						packet.TransformToDhcpAckPacket()
						self.LoadDHCPPacket(packet, result)
						if conf.loadDHCPPacket(
						 packet,
						 mac, tuple(ip), giaddr,
						 result[8], result[9]
						):
							src.logging.writeLog('DHCPACK sent to %(mac)s' % {
							 'mac': mac,
							})
							self.SendDhcpPacket(packet, source_address, 'ACK', mac, s_ip)
						else:
							src.logging.writeLog('Ignoring %(mac)s per loadDHCPPacket()' % {
							 'mac': mac,
							})
							self.LogDiscardedPacket()
					else:
						packet.TransformToDhcpNackPacket()
						self.SendDhcpPacket(packet, source_address, 'NAK', mac, s_ip)
				except Exception, e:
					src.logging.sendErrorReport('Unable to respond to %(mac)s' % {'mac': mac,}, e)
			elif not sid and ciaddr and not ip: #RENEWING or REBINDING
				if conf.NAK_RENEWALS:
					packet.TransformToDhcpNackPacket()
					self.SendDhcpPacket(packet, source_address, 'NAK', mac, 'NAK_RENEWALS')
				else:
					if source_address[0] not in ('255.255.255.255', '0.0.0.0', ''):
						src.logging.writeLog('DHCPREQUEST:RENEW received from %(mac)s' % {
						 'mac': mac,
						})
					else:
						src.logging.writeLog('DHCPREQUEST:REBIND received from %(mac)s' % {
						 'mac': mac,
						})
						
					try:
						result = self._sql_broker.lookupMAC(mac)
						if result and result[0] == s_ciaddr:
							packet.TransformToDhcpAckPacket()
							packet.SetOption('yiaddr', ciaddr)
							self.LoadDHCPPacket(packet, result)
							if conf.loadDHCPPacket(
							 packet,
							 mac, tuple(ciaddr), giaddr,
							 result[8], result[9]
							):
								self.SendDhcpPacket(packet, (s_ciaddr, 0), 'ACK', mac, s_ciaddr)
							else:
								src.logging.writeLog('Ignoring %(mac)s per loadDHCPPacket()' % {
								 'mac': mac,
								})
								self.LogDiscardedPacket()
						else:
							packet.TransformToDhcpNackPacket()
							self.SendDhcpPacket(packet, (s_ciaddr, 0), 'NAK', mac, s_ciaddr)
					except Exception, e:
						src.logging.sendErrorReport('Unable to respond to %(mac)s' % {'mac': mac,}, e)
			else:
				src.logging.writeLog('DHCPREQUEST:UNKNOWN (%(sid)s %(ciaddr)s %(ip)s) received from %(mac)s' % {
				 'sid': str(sid),
				 'ciaddr': str(ciaddr),
				 'ip': str(ip),
				 'mac': mac,
				})
				self.LogDiscardedPacket()
		else:
			self.LogDiscardedPacket()
		self.LogTimeTaken(time.time() - start_time)
		
	def LoadDHCPPacket(self, packet, result):
		"""
		Sets DHCP option fields based on values returned from the database.
		
		@type packet: L{pydhcplib.dhcp_packet.DhcpPacket}
		@param packet: The packet being updated.
		@type result: tuple(10)
		@param result: The value returned from the SQL broker.
		"""
		(ip, gateway, subnet_mask, broadcast_address,
		 domain_name, domain_name_servers, ntp_servers,
		 lease_time, subnet, serial) = result
		
		packet.SetOption('yiaddr', ipToQuad(ip))
		packet.SetOption('ip_address_lease_time', longToQuad(lease_time))
		
		#Default gateway, subnet mask, and broadcast address.
		if gateway:
			if not packet.SetOption('router', ipToQuad(gateway)):
				_logInvalidValue('gateway', gateway, subnet, serial)
		if subnet_mask:
			if not packet.SetOption('subnet_mask', ipToQuad(subnet_mask)):
				_logInvalidValue('subnet_mask', subnet_mask, subnet, serial)
		if broadcast_address:
			if not packet.SetOption('broadcast_address', ipToQuad(broadcast_address)):
				_logInvalidValue('broadcast_address', broadcast_address, subnet, serial)
				
		#Search domain/nameservers.
		if domain_name:
			if not packet.SetOption('domain_name', strToStrList(domain_name)):
				_logInvalidValue('domain_name', domain_name, subnet, serial)
		if domain_name_servers:
			if not packet.SetOption('domain_name_servers', ipsToQuads(domain_name_servers)):
				_logInvalidValue('domain_name_servers', domain_name_servers, subnet, serial)
				
		#NTP servers.
		if ntp_servers:
			if not packet.SetOption('ntp_servers', ipsToQuads(ntp_servers)):
				_logInvalidValue('ntp_servers', ntp_servers, subnet, serial)
				
	def LogDHCPAccess(self, mac):
		"""
		Increments the number of times the given MAC address has accessed this
		server. If the value exceeds the policy threshold, the MAC is ignored as
		potentially belonging to a malicious user.
		
		@type mac: basestring
		@param mac: The MAC being evaluated.
		
		@rtype: bool
		@return: True if the MAC's request should be processed.
		"""
		if conf.ENABLE_SUSPEND:
			self._stats_lock.acquire()
			try:
				assignments = self._dhcp_assignments.get(mac)
				if not assignments:
					self._dhcp_assignments[mac] = 1
				else:
					self._dhcp_assignments[mac] = assignments + 1
					if assignments + 1 > conf.SUSPEND_THRESHOLD:
						src.logging.writeLog('%(mac)s is issuing too many requests; ignoring for %(time)i seconds' % {
						 'mac': mac,
						 'time': conf.MISBEHAVING_CLIENT_TIMEOUT,
						})
						self._ignored_addresses.append([mac, conf.MISBEHAVING_CLIENT_TIMEOUT])
						return False
			finally:
				self._stats_lock.release()
		return True
		
	def LogDiscardedPacket(self):
		"""
		Increments the number of packets discarded.
		"""
		self._stats_lock.acquire()
		self._packets_discarded += 1
		self._stats_lock.release()
		
	def LogTimeTaken(self, time_taken):
		"""
		Records the time taken to process a packet.
		
		@type time_taken: float
		@param time_taken: The number of seconds the request took.
		"""
		self._stats_lock.acquire()
		self._time_taken += time_taken
		self._stats_lock.release()
		
	def SendDhcpPacket(self, packet, address, response_type, mac, client_ip):
		"""
		Sends the given packet to the right destination based on its properties.
		
		If the request originated from a host that knows its own IP, the packet
		is transmitted via unicast; in the event of a relayed request, it is sent
		to the 'server port', rather than the 'client port', per RFC 2131.
		
		If it was picked up as a broadcast packet, it is sent to the local subnet
		via the same mechanism, but to the 'client port'.
		
		@type packet: L{pydhcplib.dhcp_packet.DhcpPacket}
		@param packet: The packet to be transmitted.
		@type address: tuple
		@param address: The address from which the packet was received:
			(host, port)
		@type response_type: basestring
		@param response_type: The DHCP subtype of this response: 'OFFER', 'ACK',
			'NAK'
		@type mac: basestring
		@param mac: The MAC of the client for which this packet is destined.
		@type client_ip: basestring
		@param client_ip: The IP being assigned to the client.
		
		@rtype: int
		@return: The number of bytes transmitted.
		"""
		relay = False
		ip = port = None
		if address[0] not in ('255.255.255.255', '0.0.0.0', ''): #Unicast.
			giaddr = packet.GetGiaddr()
			if giaddr and not giaddr == [0,0,0,0]: #Relayed request.
				ip = '.'.join(map(str, giaddr))
				port = conf.DHCP_SERVER_PORT
				relay = True
			else: #Request directly from client, routed or otherwise.
				ip = address[0]
				port = conf.DHCP_CLIENT_PORT
		else: #Broadcast.
			ip = '255.255.255.255'
			port = self.emit_port
			
		bytes = self.SendDhcpPacketTo(packet, ip, port)
		src.logging.writeLog('DHCP%(type)s sent to %(mac)s for %(ip)s [%(bytes)i bytes|relayed = %(relay)s]' % {
			 'type': response_type,
			 'mac': mac,
			 'ip': client_ip,
			 'bytes': bytes,
			 'relay': str(relay),
		})
		return bytes
		
		
class DHCPService(threading.Thread):
	"""
	A thread that handles DHCP requests indefinitely, daemonically.
	"""
	_dhcp_server = None #: The handler that responds to DHCP requests.
	
	def __init__(self):
		"""
		Sets up the DHCP server.
		
		
		@raise Exception: If a problem occurs while binding the sockets needed
			to handle DHCP traffic.
		"""
		threading.Thread.__init__(self)
		self.daemon = True
		
		self._dhcp_server = _DHCPServer(
		 conf.DHCP_SERVER_IP,
		 conf.DHCP_SERVER_PORT,
		 conf.DHCP_CLIENT_PORT
		)
		
		src.logging.writeLog('Configured DHCP server')
		
	def run(self):
		"""
		Runs the DHCP server indefinitely.
		
		In the event of an unexpected error, e-mail will be sent and processing
		will continue with the next request.
		"""
		src.logging.writeLog('Running DHCP server')
		while True:
			try:
				self._dhcp_server.GetNextDhcpPacket()
			except select.error:
				src.logging.writeLog('Suppressed non-fatal select() error in DHCP module')
			except Exception, e:
				src.logging.sendErrorReport('Unhandled exception', e)
				
	def pollStats(self):
		"""
		Updates the performance statistics in the in-memory stats-log and
		implicitly updates the ignored MACs values.
		"""
		(processed, discarded, time_taken, ignored_macs) = self._dhcp_server.GetStats()
		src.logging.writePollRecord(processed, discarded, time_taken, ignored_macs)
		
