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

_SERVER_ADDRESS = '0.0.0.0'
_SERVER_PORT = 67
_CLIENT_PORT = 68

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
		print 1, packet, dir(packet)
		
	def HandleDhcpRequest(self, packet):
		print 2, packet, dir(packet)
		
def lookupMAC(mac):
	try:
		mysql_db = MySQLdb.connect(host="localhost", user="aurica", passwd="misha", db="hymmnoserver")
		mysql_cur = mysql_db.cursor()
		
		mysql_cur.execute("SELECT ip_address FROM maps WHERE mac = %s LIMIT 1", (mac,))
		result = mysql_cur.fetchone()
		if result:
			return result[0]
		return None
	except:
		print "Something went horribly wrong!"
	finally:
		try:
			mysql_cur.close()
			mysql_db.close()
		except:
			pass
			
server = DHCPServer()
while True:
	server.GetNextDHCPPacket()