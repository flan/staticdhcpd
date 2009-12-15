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
import MySQLdb

import pydhcplib.dhcp_network
import pydhcplib.dhcp_packet
import pydhcplib.type_hw_addr
import pydhcplib.type_strlist

_SERVER_ADDRESS = '0.0.0.0'
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
				offer.SetOption('ip_address_lease_time', 1209600)
				
				self.SendPacket(offer)
			else:
				_ignored_addresses.append([mac, _IGNORE_TIMEOUT])
				
	def HandleDhcpRequest(self, packet):
		packet.TransformToDhcpNackPacket()
		self.SendPacket(packet)
		
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
	