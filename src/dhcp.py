import threading
import time

import conf

import src.logging
import sql

import pydhcplib.dhcp_network
import pydhcplib.dhcp_packet
import pydhcplib.type_hw_addr
import pydhcplib.type_strlist

class DHCPServer(pydhcplib.dhcp_network.DhcpNetwork):
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
		self._packets_processed_lock = threading.Lock()
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
		
		self._sql_broker = sql.SQL_BROKER()
		
	def HandleDhcpDiscover(self, packet):
		start_time = time.time()
		mac = pydhcplib.type_hw_addr.hwmac(packet.GetHardwareAddress())
		if not [None for (ignored_mac, timeout) in self._ignored_addresses if mac == ignored_mac]:
			self._logDHCPAccess(mac)
			
			src.logging.writeLog('DHCPDISCOVER received from %(mac)s' % {
			 'mac': mac,
			})
			
			ip = self._sql_broker.lookupMAC(mac)
			if ip:
				offer = pydhcplib.dhcp_packet.DhcpPacket()
				offer.CreateDhcpOfferPacketFrom(packet)
				
				associated_ip = [int(i) for i in ip.split('.')]
				offer.SetOption('yiaddr', associated_ip)
				offer.SetOption('server_identifier', [int(i) for i in self._server_address.split('.')])
				conf.loadDHCPPacket(offer, associated_ip)
				
				self.SendDhcpPacket(offer)
				src.logging.writeLog('DHCPOFFER sent to %(mac)s' % {
				 'mac': mac,
				})
			else:
				src.logging.writeLog('%(mac)s unknown; ignoring for %(time)i seconds' % {
				 'mac': mac,
				 'time': conf.UNAUTHORIZED_CLIENT_TIMEOUT,
				})
				self._stats_lock.acquire()
				self._ignored_addresses.append([mac, conf.UNAUTHORIZED_CLIENT_TIMEOUT])
				self._stats_lock.release()
		self._logTimeTaken(time.time() - start_time)
		
	def HandleDhcpRequest(self, packet):
		start_time = time.time()
		mac = pydhcplib.type_hw_addr.hwmac(packet.GetHardwareAddress())
		if not [None for (ignored_mac, timeout) in self._ignored_addresses if mac == ignored_mac]:
			self._logDHCPAccess(mac)
			
			ip = packet.GetOption("request_ip_address")
			sid = packet.GetOption("server_identifier")
			ciaddr = packet.GetOption("ciaddr")
			s_ip = '.'.join(map(str, ip))
			s_sid = '.'.join(map(str, sid))
			s_ciaddr = '.'.join(map(str, ciaddr))
			
			if sid != [0,0,0,0] and ciaddr == [0,0,0,0]:
				#SELECTING
				src.logging.writeLog('DHCPREQUEST:SELECTING received from %(mac)s' % {
				 'mac': mac,
				})
				if s_sid == self._server_address: #Chosen!
					client_ip = s_ip
					if not conf.SKIP_REQUEST_VALIDATION:
						client_ip = self._sql_broker.lookupMAC(mac)
					if client_ip == s_ip:
						packet.TransformToDhcpAckPacket()
						packet.SetOption('yiaddr', ip)
						conf.loadDHCPPacket(packet, ip)
						
						src.logging.writeLog('DHCPACK sent to %(mac)s' % {
						 'mac': mac,
						})
					else:
						packet.TransformToDhcpNackPacket()
						src.logging.writeLog('DHCPNAK sent to %(mac)s' % {
						 'mac': mac,
						})
					self.SendDhcpPacket(packet)
			elif sid == [0,0,0,0] and ciaddr == [0,0,0,0] and ip:
				#INIT-REBOOT
				src.logging.writeLog('DHCPREQUEST:INIT-REBOOT received from %(mac)s' % {
				 'mac': mac,
				})
				client_ip = s_ip
				if not conf.SKIP_REQUEST_VALIDATION:
					client_ip = self._sql_broker.lookupMAC(mac)
				if client_ip == s_ip:
					packet.TransformToDhcpAckPacket()
					packet.SetOption('yiaddr', ip)
					conf.loadDHCPPacket(packet, ip)
					
					src.logging.writeLog('DHCPACK sent to %(mac)s' % {
					 'mac': mac,
					})
				else:
					packet.TransformToDhcpNackPacket()
					src.logging.writeLog('DHCPNAK sent to %(mac)s' % {
					 'mac': mac,
					})
				self.SendDhcpPacket(packet)
			elif sid == [0,0,0,0] and ciaddr != [0,0,0,0] and not ip:
				if packet.GetOption("ciaddr") == [255,255,255,255]:
					#REBINDING
					src.logging.writeLog('DHCPREQUEST:REBIND received from %(mac)s' % {
					 'mac': mac,
					})
					src.logging.writeLog('Requiring %(mac)s to initiate DISCOVER' % {
					 'mac': mac,
					})
				else:
					#RENEWING
					src.logging.writeLog('DHCPREQUEST:RENEW received from %(mac)s' % {
					 'mac': mac,
					})
					if conf.ALLOW_DHCP_RENEW:
						client_ip = self._sql_broker.lookupMAC(mac)
						if client_ip == s_ciaddr:
							packet.TransformToDhcpAckPacket()
							packet.SetOption('yiaddr', ciaddr)
							conf.loadDHCPPacket(packet, ciaddr)
							
							src.logging.writeLog('DHCPACK sent to %(mac)s' % {
							 'mac': mac,
							})
						else:
							packet.TransformToDhcpNackPacket()
							src.logging.writeLog('DHCPNAK sent to %(mac)s' % {
							 'mac': mac,
							})
						self.SendDhcpPacket(packet, s_ciaddr)
					else:
						src.logging.writeLog('Requiring %(mac)s to initiate DISCOVER' % {
						 'mac': mac,
						})
			else:
				src.logging.writeLog('DHCPREQUEST:UNKNOWN received from %(mac)s' % {
				 'mac': mac,
				})
				self._stats_lock.acquire()
				self._ignored_addresses.append([mac, conf.UNAUTHORIZED_CLIENT_TIMEOUT])
				self._stats_lock.release()
				src.logging.writeLog('Ignoring %(mac)s for %(time)i seconds' % {
				 'mac': mac,
				 'time': conf.UNAUTHORIZED_CLIENT_TIMEOUT,
				})
		self._logTimeTaken(time.time() - start_time)
		
	def SendDhcpPacket(self, packet, _ip=None):
		if _ip:
			bytes = self.SendDhcpPacketTo(packet, _ip)
			src.logging.writeLog('%(bytes)i-byte packet sent to client at %(ip)s' % {
			 'bytes': bytes,
			 'ip': _ip,
			})
			return bytes
		else:
			giaddr = packet.GetGiaddr()
			if giaddr == [0, 0, 0, 0]:
				bytes = self.SendDhcpPacketTo(packet, '255.255.255.255')
				src.logging.writeLog('%(bytes)i-byte packet sent to broadcast address' % {
				 'bytes': bytes,
				})
				return bytes
			else:
				giaddr = '.'.join(map(str, giaddr))
				bytes = self.SendDhcpPacketTo(packet, giaddr)
				src.logging.writeLog('%(bytes)i-byte packet sent to relay gateway %(giaddr)s' % {
				 'bytes': bytes,
				 'giaddr': giaddr,
				})
				return bytes
				
	def GetNextDhcpPacket(self):
		if pydhcplib.dhcp_network.DhcpNetwork.GetNextDhcpPacket(self):
			self._stats_lock.acquire()
			self._packets_processed += 1
			self._stats_lock.release()
			
	def _logTimeTaken(self, time_taken):
		self._stats_lock.acquire()
		self._time_taken += time_taken
		self._stats_lock.release()
		
	def _logDiscardedPacket(self):
		self._stats_lock.acquire()
		self._packets_discarded += 1
		self._stats_lock.release()
		
	def _logDHCPAccess(self, mac):
		self._stats_lock.acquire()
		assignments = self._dhcp_assignments.get(mac):
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
		self._stats_lock.release()
		
	def getStats(self):
		self._stats_lock.acquire()
		try:
			for i in range(len(self._ignored_addresses)):
				self._ignored_addresses[i][1] -= conf.POLLING_INTERVAL
			self._ignored_addresses = [address for address in self._ignored_addresses if address[1] > 0]
			
			stats = (self._packets_processed, self._packets_discarded, self._time_taken, len(self._ignored_addresses))
			
			self._dhcp_assignments = {}
			self._packets_processed = 0
			self._packets_discarded = 0
			self._time_taken = 0.0
			
			return stats
		finally:
			self._stats_lock.release()
			
class DHCPService(threading.Thread):
	_dhcp_server = None
	
	def __init__(self):
		threading.Thread.__init__(self)
		self.daemon = True
		
		self._dhcp_server = DHCPServer(
		 constants.SERVER_IP, constants.SERVER_PORT, constants.CLIENT_PORT
		)
		
		src.logging.writeLog('Configured DHCP server')
		
	def run(self):
		src.logging.writeLog('Running DHCP server')
		while True:
			self._dhcp_server.GetNextDhcpPacket()
			
	def getStats(self):
		(processed, discarded, time_taken, ignored_macs) = self._dhcp_server.getStats()
		src.logging.writePollRecord(processed, discarded, time_taken, ignored_macs)
		