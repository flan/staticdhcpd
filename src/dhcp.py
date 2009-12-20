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
		#If this is a relayed request, decide whether to handle it or not.
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
		if pydhcplib.dhcp_network.DhcpNetwork.GetNextDhcpPacket(self):
			self._stats_lock.acquire()
			self._packets_processed += 1
			self._stats_lock.release()
			
	def GetStats(self):
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
					
					offer.SetOption('server_identifier', [int(i) for i in self._server_address.split('.')])
					self.LoadDHCPPacket(offer, result)
					giaddr = packet.GetGiaddr()
					if not giaddr or giaddr == [0,0,0,0]:
						giaddr = None
					else:
						giaddr = tuple(giaddr)
					if conf.loadDHCPPacket(
					 offer,
					 mac, tuple([int(i) for i in result[0].split('.')]), giaddr,
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
							 mac, tuple(map(int, result[0].split('.'))), giaddr,
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
			elif not sid and ciaddr and not ip: #REBINDING or RENEWING
				if conf.NAK_RENEWALS:
					packet.TransformToDhcpNackPacket()
					self.SendDhcpPacket(packet, source_address, 'NAK', mac, 'NAK_RENEWALS')
				else:
					src.logging.writeLog('DHCPREQUEST:RENEW received from %(mac)s' % {
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
		(ip, gateway, subnet_mask, broadcast_address, domain_name, domain_name_servers, ntp_servers, lease_time) = result
		
		packet.SetOption('yiaddr', [int(i) for i in ip.split('.')])
		packet.SetOption('ip_address_lease_time', longToQuad(lease_time))
		
		#Default gateway, subnet mask, and broadcast address.
		if gateway:
			packet.SetOption('router', [int(i) for i in gateway.split('.')])
		if subnet_mask:
			packet.SetOption('subnet_mask', [int(i) for i in subnet_mask.split('.')])
		if broadcast_address:
			packet.SetOption('broadcast_address', [int(i) for i in broadcast_address.split('.')])
			
		#Search domain/nameservers.
		if domain_name:
			packet.SetOption('domain_name', pydhcplib.type_strlist.strlist(str(domain_name)).list())
		if domain_name_servers:
			dns_list = []
			for dns in domain_name_servers.split(','):
				dns_list += [int(i) for i in dns.strip().split('.')]
			packet.SetOption('domain_name_servers', dns_list)
			
		#NTP servers.
		if ntp_servers:
			ntp_list = []
			for ntp in ntp_servers.split(','):
				ntp_list += [int(i) for i in ntp.strip().split('.')]
			packet.SetOption('ntp_servers', ntp_list)
			
	def LogDHCPAccess(self, mac):
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
		self._stats_lock.acquire()
		self._packets_discarded += 1
		self._stats_lock.release()
		
	def LogTimeTaken(self, time_taken):
		self._stats_lock.acquire()
		self._time_taken += time_taken
		self._stats_lock.release()
		
	def SendDhcpPacket(self, packet, address, response_type, mac, client_ip):
		ip = port = None
		if address[0] not in ('255.255.255.255', '0.0.0.0', ''): #Unicast.
			giaddr = packet.GetGiaddr()
			if giaddr and not giaddr == [0,0,0,0]: #Relayed request.
				ip = '.'.join(map(str, giaddr))
				port = conf.DHCP_SERVER_PORT
			else: #Request directly from client, routed or otherwise.
				ip = address[0]
				port = conf.DHCP_CLIENT_PORT
		else: #Broadcast.
			ip = '255.255.255.255'
			port = self.emit_port
			
		bytes = self.SendDhcpPacketTo(packet, ip, port)
		src.logging.writeLog('DHCP%(type)s sent to %(mac)s for %(ip)s [%(bytes)i bytes]' % {
			 'type': response_type,
			 'mac': mac,
			 'ip': client_ip,
			 'bytes': bytes,
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
		