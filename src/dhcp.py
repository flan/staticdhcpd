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
	q = [l % 256]
	l /= 256
	q.insert(0, l % 256)
	l /= 256
	q.insert(0, l % 256)
	l /= 256
	q.insert(0, l % 256)
	return q
	
class _DHCPServer(pydhcplib.dhcp_network.DhcpNetwork):
	_server_address = None
	_server_port = None
	_client_port = None
	
	_sql_broker = None
	
	_stats_lock = None
	_packets_processed = 0
	_packets_discarded = 0
	_time_taken = 0.0
	_dhcp_assignments = None
	_ignored_addresses = None
	
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
					if conf.loadDHCPPacket(offer, mac, tuple([int(i) for i in result[0].split('.')]), giaddr):
						src.logging.writeLog('DHCPOFFER sent to %(mac)s' % {
						 'mac': mac,
						})
						self.SendDhcpPacket(offer, source_address)
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
						if not ip or (result and result[0] == s_ip):
							packet.TransformToDhcpAckPacket()
							self.LoadDHCPPacket(packet, result)
							if conf.loadDHCPPacket(packet, mac, tuple(result[0]), giaddr):
								src.logging.writeLog('DHCPACK sent to %(mac)s' % {
								 'mac': mac,
								})
								self.SendDhcpPacket(packet, source_address)
							else:
								src.logging.writeLog('Ignoring %(mac)s per loadDHCPPacket()' % {
								 'mac': mac,
								})
								self.LogDiscardedPacket()
						else:
							packet.TransformToDhcpNackPacket()
							src.logging.writeLog('DHCPNAK sent to %(mac)s' % {
							 'mac': mac,
							})
							self.SendDhcpPacket(packet, source_address)
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
						if conf.loadDHCPPacket(packet, mac, tuple(ip), giaddr):
							src.logging.writeLog('DHCPACK sent to %(mac)s' % {
							 'mac': mac,
							})
							self.SendDhcpPacket(packet, source_address)
						else:
							src.logging.writeLog('Ignoring %(mac)s per loadDHCPPacket()' % {
							 'mac': mac,
							})
							self.LogDiscardedPacket()
					else:
						packet.TransformToDhcpNackPacket()
						src.logging.writeLog('DHCPNAK sent to %(mac)s' % {
						 'mac': mac,
						})
						self.SendDhcpPacket(packet, source_address)
				except Exception, e:
					src.logging.sendErrorReport('Unable to respond to %(mac)s' % {'mac': mac,}, e)
			elif not sid and ciaddr and not ip: #REBINDING or RENEWING
				if conf.NAK_RENEWALS:
					packet.TransformToDhcpNackPacket()
					src.logging.writeLog('DHCPNAK sent to %(mac)s per NAK_RENEWALS' % {
					 'mac': mac,
					})
					self.SendDhcpPacket(packet, source_address)
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
							if conf.loadDHCPPacket(packet, mac, tuple(ciaddr), giaddr):
								src.logging.writeLog('DHCPACK sent to %(mac)s' % {
								 'mac': mac,
								})
								self.SendDhcpPacket(packet, (s_ciaddr, 0))
							else:
								src.logging.writeLog('Ignoring %(mac)s per loadDHCPPacket()' % {
								 'mac': mac,
								})
								self.LogDiscardedPacket()
						else:
							packet.TransformToDhcpNackPacket()
							src.logging.writeLog('DHCPNAK sent to %(mac)s' % {
							 'mac': mac,
							})
							self.SendDhcpPacket(packet, (s_ciaddr, 0))
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
		(ip, gateway, subnet_mask, broadcast_address, domain_name, domain_name_servers, lease_time) = result
		
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
			packet.SetOption('domain_name_server', dns_list)
			
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
		
	def SendDhcpPacket(self, packet, address):
		if address[0] not in ('255.255.255.255', '0.0.0.0', ''): #Unicast.
			port = destination_ip = None
			giaddr = packet.GetGiaddr()
			if giaddr and not giaddr == [0,0,0,0]: #Relayed request.
				port = conf.DHCP_SERVER_PORT
				destination_ip = '.'.join(map(str, giaddr))
			else: #Request directly from client, routed or otherwise.
				port = conf.DHCP_CLIENT_PORT
				destination_ip = address[0]
			return self.SendDhcpPacketTo(packet, destination_ip, port)
		else: #Broadcast.
			return self.SendDhcpPacketTo(packet, '255.255.255.255')
			
			
class DHCPService(threading.Thread):
	_dhcp_server = None
	
	def __init__(self):
		threading.Thread.__init__(self)
		self.daemon = True
		
		self._dhcp_server = _DHCPServer(
		 conf.DHCP_SERVER_IP,
		 conf.DHCP_SERVER_PORT,
		 conf.DHCP_CLIENT_PORT
		)
		
		src.logging.writeLog('Configured DHCP server')
		
	def run(self):
		src.logging.writeLog('Running DHCP server')
		while True:
			try:
				self._dhcp_server.GetNextDhcpPacket()
			except select.error:
				src.logging.writeLog('Suppressed non-fatal select() error in DHCP module')
			except Exception, e:
				src.logging.sendErrorReport('Unhandled exception', e)
				
	def getStats(self):
		(processed, discarded, time_taken, ignored_macs) = self._dhcp_server.GetStats()
		src.logging.writePollRecord(processed, discarded, time_taken, ignored_macs)
		