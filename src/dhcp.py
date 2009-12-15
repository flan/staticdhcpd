import threading

import constants
import sql

import pydhcplib.dhcp_network
import pydhcplib.dhcp_packet
import pydhcplib.type_hw_addr
import pydhcplib.type_strlist

_IGNORE_TIMEOUT = 180

class DHCPServer(pydhcplib.dhcp_network.DhcpNetwork):
	_server_address = None
	_server_port = None
	_client_port = None
	_ignored_addresses = None
	
	def __init__(self, server_address, server_port, client_port):
		self._server_address = server_address
		self._server_port = server_port
		self._client_port = client_port
		
		self._ignored_addresses = []
		
		pydhcplib.dhcp_network.DhcpNetwork.__init__(
		 self, server_address, server_port, client_port
		)
		
		self.EnableBroadcast()
		self.EnableReuseaddr()
		self.CreateSocket()
		self.BindToAddress()
		
	def HandleDhcpDiscover(self, packet):
		mac = packet.GetHardwareAddress()
		if not [None for (ignored_mac, timeout) in _ignored_addresses if mac == ignored_mac]:
			constants.writeLog('DHCPDISCOVER received from %(mac)s' % {
			 'mac': mac,
			})
			
			ip = lookupMAC(pydhcplib.type_hw_addr.hwmac(mac))
			if ip:
				offer = pydhcplib.dhcp_packet.DhcpPacket()
				offer.CreateDhcpOfferPacketFrom(packet)
				
				offer.SetOption('yiaddr', [int(i) for i in ip.split('.')])
				offer.SetOption('server_identifier', [int(i) for i in _SERVER_ADDRESS.split('.')])
				self.LoadDhcpPacket(offer)
				
				self.SendDhcpPacket(offer)
				constants.writeLog('DHCPOFFER sent to %(mac)s' % {
				 'mac': mac,
				})
			else:
				constants.writeLog('%(mac)s unknown; ignoring' % {
				 'mac': mac,
				})
				_ignored_addresses.append([mac, _IGNORE_TIMEOUT])
				
	def HandleDhcpRequest(self, packet):
		mac = packet.GetHardwareAddress()
		if not [None for (ignored_mac, timeout) in _ignored_addresses if mac == ignored_mac]:
			ip = packet.GetOption("request_ip_address")
			sid = packet.GetOption("server_identifier")
			ciaddr = packet.GetOption("ciaddr")
			s_ip = '.'.join(map(str, ip))
			s_sid = '.'.join(map(str, sid))
			s_ciaddr = '.'.join(map(str, ciaddr))

			if sid != [0,0,0,0] and ciaddr == [0,0,0,0]:
				#SELECTING
				constants.writeLog('DHCPREQUEST:SELECTING received from %(mac)s' % {
				 'mac': mac,
				})
				if s_sid == self._server_address: #Chosen!
					client_ip = lookupMAC(pydhcplib.type_hw_addr.hwmac(mac))
					if client_ip == s_ip:
						packet.TransformToDhcpAckPacket()
						packet.SetOption('yiaddr', ip)
						self.LoadDhcpPacket(offer)
						
						constants.writeLog('DHCPACK sent to %(mac)s' % {
						 'mac': mac,
						})
					else:
						packet.TransformToDhcpNackPacket()
						constants.writeLog('DHCPNAK sent to %(mac)s' % {
						 'mac': mac,
						})
					self.SendDhcpPacket(packet)
			elif sid == [0,0,0,0] and ciaddr == [0,0,0,0] and ip:
				#INIT-REBOOT
				constants.writeLog('DHCPREQUEST:INIT-REBOOT received from %(mac)s' % {
				 'mac': mac,
				})
				client_ip = lookupMAC(pydhcplib.type_hw_addr.hwmac(mac))
				if client_ip == s_ip:
					packet.TransformToDhcpAckPacket()
					packet.SetOption('yiaddr', ip)
					self.LoadDhcpPacket(offer)
					
					constants.writeLog('DHCPACK sent to %(mac)s' % {
					 'mac': mac,
					})
				else:
					packet.TransformToDhcpNackPacket()
					constants.writeLog('DHCPNAK sent to %(mac)s' % {
					 'mac': mac,
					})
				self.SendDhcpPacket(packet)
			elif sid == [0,0,0,0] and ciaddr != [0,0,0,0] and not ip:
				if packet.GetOption("ciaddr") == [255,255,255,255]:
					#REBINDING
					constants.writeLog('DHCPREQUEST:REBINDING received from %(mac)s' % {
					 'mac': mac,
					})
					constants.writeLog('Requiring %(mac)s to initiate DISCOVER' % {
					 'mac': mac,
					})
				else:
					#RENEWING
					constants.writeLog('DHCPREQUEST:RENEWING received from %(mac)s' % {
					 'mac': mac,
					})
					
					client_ip = lookupMAC(pydhcplib.type_hw_addr.hwmac(mac))
					if client_ip == s_ciaddr:
						packet.TransformToDhcpAckPacket()
						packet.SetOption('yiaddr', ciaddr)
						self.LoadDhcpPacket(offer)
						
						constants.writeLog('DHCPACK sent to %(mac)s' % {
						 'mac': mac,
						})
					else:
						packet.TransformToDhcpNackPacket()
						constants.writeLog('DHCPNAK sent to %(mac)s' % {
						 'mac': mac,
						})
					self.SendDhcpPacket(packet, s_ciaddr)
			else:
				constants.writeLog('DHCPREQUEST:UNKNOWN received from %(mac)s' % {
				 'mac': mac,
				})
				_ignored_addresses.append([mac, _IGNORE_TIMEOUT])
				constants.writeLog('Ignoring %(mac)s' % {
				 'mac': mac,
				})
				
	def SendDhcpPacket(self, packet, _ip=None):
		if _ip:
			bytes = self.SendDhcpPacketTo(packet, _ip)
			constants.writeLog('%(bytes)i-byte packet sent to client at %(ip)s' % {
			 'bytes': bytes,
			 'ip': _ip,
			})
			return bytes
		else:
			giaddr = packet.GetGiaddr()
			if giaddr == [0, 0, 0, 0]:
				bytes = self.SendDhcpPacketTo(packet, '255.255.255.255')
				constants.writeLog('%(bytes)i-byte sent to broadcast address' % {
				 'bytes': bytes,
				})
				return bytes
			else:
				giaddr = '.'.join(map(str, giaddr))
				bytes = self.SendDhcpPacketTo(packet, giaddr)
				constants.writeLog('%(bytes)i-byte sent to relay gateway %(giaddr)s' % {
				 'bytes': bytes,
				 'giaddr': giaddr,
				})
				return bytes
				
	def LoadDhcpPacket(self, packet):
		packet.SetOption('ip_address_lease_time', [0, 18, 117, 0]) #Should be two weeks.
		packet.SetOption('domain_name', pydhcplib.type_strlist.strlist("cciwireless.ca").list())
		packet.SetOption('router', [192,168,168,1])
		packet.SetOption('time_server', [192,168,168,100,127,0,0,1])
		packet.SetOption('name_server', [192,168,168,101,127,0,0,2])
		packet.SetOption('subnet_mask', [255,255,255,0])
		packet.SetOption('broadcast_address', [192,168,168,255])
		
		packet.SetOption('smtp_server', [66,38,149,131])
		packet.SetOption('pop3_server', [66,38,149,131])
		packet.SetOption('default_www_server', [66,38,149,130])
		
class DHCPService(threading.Thread):
	_dhcp_server = None
	
	def __init__(self, server_address, server_port, client_port):
		threading.Thread.__init__(self)
		self.daemon = True
		
		self._dhcp_server = DHCPServer(
		 constants.SERVER_IP, constants.SERVER_PORT, constants.CLIENT_PORT
		)
		
		constants.writeLog('Configured DHCP server')
		
	def run(self):
		constants.writeLog('Running DHCP server')
		while True:
			self._dhcp_server.GetNextDhcpPacket()
			