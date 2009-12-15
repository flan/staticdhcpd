# -*- encoding: utf-8 -*-
"""
staticDHCPd module: main

Purpose
=======
 Runs a staticDHCPd server.
 
Legal
=====
 All code, unless otherwise indicated, is original, and subject to the terms of
 the GNU General Public License version 3, which is provided in COPYING.
 
 (C) Neil Tallim, 2009
"""
import struct

import MySQLdb

import pydhcplib.dhcp_network
import pydhcplib.dhcp_packet
import pydhcplib.type_hw_addr
import pydhcplib.type_strlist

_SERVER_ADDRESS = '192.168.122.1'
_SERVER_PORT = 67
_CLIENT_PORT = 68

_IGNORE_TIMEOUT = 180
_ignored_addresses = []

class DHCPServer(pydhcplib.dhcp_network.DhcpNetwork):
	def __init__(self):
		self.port_destination = _CLIENT_PORT
		
		pydhcplib.dhcp_network.DhcpNetwork.__init__(
		 self,
		 _SERVER_ADDRESS,
		 _SERVER_PORT,
		 _CLIENT_PORT
		)
		
		self.EnableBroadcast()
		self.EnableReuseaddr()
		self.CreateSocket()
		self.BindToAddress()
		
	def HandleDhcpDiscover(self, packet):
		mac = packet.GetHardwareAddress()
		if not [None for (ignored_mac, timeout) in _ignored_addresses if mac == ignored_mac]:
			ip = lookupMAC(pydhcplib.type_hw_addr.hwmac(mac))
			if ip:
				offer = pydhcplib.dhcp_packet.DhcpPacket()
				offer.CreateDhcpOfferPacketFrom(packet)
				
				offer.SetOption('yiaddr', [int(i) for i in ip.split('.')])
				offer.SetOption('server_identifier', [int(i) for i in _SERVER_ADDRESS.split('.')])
				offer.SetOption('ip_address_lease_time', [0, 18, 117, 0])
				offer.SetOption('domain_name', pydhcplib.type_strlist.strlist("cciwireless.ca").list())
				offer.SetOption('router', [192,168,168,1])
				offer.SetOption('time_server', [192,168,168,100,127,0,0,1])
				offer.SetOption('subnet_mask', [255,255,255,0])
				offer.SetOption('broadcast_address', [192,168,168,255])
				
				self.SendDhcpPacket(offer)
			else:
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
				if s_sid == _SERVER_ADDRESS: #Chosen!
					client_ip = lookupMAC(pydhcplib.type_hw_addr.hwmac(mac))
					if client_ip == s_ip:
						packet.TransformToDhcpAckPacket()
						packet.SetOption('yiaddr', ip)
						packet.SetOption('ip_address_lease_time', [0, 18, 117, 0])
						packet.SetOption('domain_name', pydhcplib.type_strlist.strlist("cciwireless.ca").list())
						packet.SetOption('router', [192,168,168,1])
						packet.SetOption('time_server', [192,168,168,100,127,0,0,1])
						packet.SetOption('subnet_mask', [255,255,255,0])
						packet.SetOption('broadcast_address', [192,168,168,255])
					else:
						packet.TransformToDhcpNackPacket()
					self.SendDhcpPacket(packet)
			elif sid == [0,0,0,0] and ciaddr == [0,0,0,0] and ip:
				#INIT-REBOOT
				client_ip = lookupMAC(pydhcplib.type_hw_addr.hwmac(mac))
				if client_ip == s_ip:
					packet.TransformToDhcpAckPacket()
					packet.SetOption('yiaddr', ip)
					packet.SetOption('ip_address_lease_time', [0, 18, 117, 0])
					packet.SetOption('domain_name', pydhcplib.type_strlist.strlist("cciwireless.ca").list())
					packet.SetOption('router', [192,168,168,1])
					packet.SetOption('time_server', [192,168,168,100,127,0,0,1])
					packet.SetOption('subnet_mask', [255,255,255,0])
					packet.SetOption('broadcast_address', [192,168,168,255])
				else:
					packet.TransformToDhcpNackPacket()
				self.SendDhcpPacket(packet)
			elif sid == [0,0,0,0] and ciaddr != [0,0,0,0] and not ip:
				if packet.GetOption("ciaddr") == [255,255,255,255]:
					#REBINDING
					pass #Ignore it; it'll rediscover later.
				else:
					#RENEWING
					client_ip = lookupMAC(pydhcplib.type_hw_addr.hwmac(mac))
					if client_ip == s_ciaddr:
						packet.TransformToDhcpAckPacket()
						packet.SetOption('yiaddr', ciaddr)
						packet.SetOption('ip_address_lease_time', [0, 18, 117, 0])
						packet.SetOption('domain_name', pydhcplib.type_strlist.strlist("cciwireless.ca").list())
						packet.SetOption('router', [192,168,168,1])
						packet.SetOption('time_server', [192,168,168,100,127,0,0,1])
						packet.SetOption('subnet_mask', [255,255,255,0])
						packet.SetOption('broadcast_address', [192,168,168,255])
					else:
						packet.TransformToDhcpNackPacket()
					self.SendDhcpPacket(packet, s_ciaddr)
			else:
				#Something's not right.
				_ignored_addresses.append([mac, _IGNORE_TIMEOUT])
				
def lookupMAC(mac):
	try:
		mysql_db = MySQLdb.connect(host="localhost", user="testuser", passwd="testpass", db="dhcpd")
		mysql_cur = mysql_db.cursor()
		
		mysql_cur.execute("SELECT ip FROM maps WHERE mac = %s LIMIT 1", (mac,))
		result = mysql_cur.fetchone()
		if result:
			return result[0]
		return None
	except Exception, e:
		print e
	finally:
		try:
			mysql_cur.close()
			mysql_db.close()
		except:
			pass
			
server = DHCPServer()
while True:
	server.GetNextDhcpPacket()
	