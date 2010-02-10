# -*- encoding: utf-8 -*-
"""
pydhcplib module: dhcp_network

Purpose
=======
 Processes DHCP packets.
 
Legal
=====
 This file is part of libpydhcpserver.
 libpydhcpserver is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program. If not, see <http://www.gnu.org/licenses/>.
 
 (C) Neil Tallim, 2010 <flan@uguu.ca>
 (C) Mathieu Ignacio, 2008 <mignacio@april.org>
"""
import select
import socket
import threading

import dhcp_packet

class DHCPNetwork(object):
	_server_address = None
	_server_port = None
	_client_port = None
	_dhcp_socket = None
	_response_socket = None
	
	def __init__(self, server_address, server_port, client_port):
		self._server_address = server_address
		self._server_port = server_port
		self._client_port = client_port
		
	# Networking stuff
	def _bindToAddress(self):
		try:
			if self._server_address:
				self._response_socket.bind((self._server_address, 0))
			self._dhcp_socket.bind(('', self._server_port))
		except socket.error,msg:
			raise Exception('pydhcplib.DhcpNetwork socket unable to bind to address: %(err)s' % {'err': str(msg),})
			
	def _createSocket(self):
		try:
			self._dhcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			if self._server_address:
				self._response_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			else:
				self._response_socket = self._dhcp_socket
		except socket.error, msg:
			raise Exception('pydhcplib.DhcpNetwork socket creation error: %(err)s' % {'err': str(msg),})
			
		try:
			self._response_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		except socket.error, msg:
			raise Exception('pydhcplib.DhcpNetwork socket unable to set SO_BROADCAST: %(err)s' % {'err': str(msg),})
			
		try: 
			self._dhcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		except socket.error, msg :
			raise Exception('pydhcplib.DhcpNetwork socket unable to set SO_REUSEADDR: %(err)s' % {'err': str(msg),})
			
	def _getNextDHCPPacket(self, timeout=60):
		"""
		Blocks for up to C{timeout} seconds while waiting for a packet to
		arrive; if one does, a thread is spawned to process it.
		
		@type timeout: int
		@param timeout: The number of seconds to wait before returning.
		
		@rtype: L{dhcp_packet.DhcpPacket}|None
		@return: The received packet, or None if nothing was received.
		"""
		data = None
		while not data:
			(data_input, data_output, data_except) = select.select([self._dhcp_socket], [], [], timeout)
			if data_input:
				(data, source_address) = self._dhcp_socket.recvfrom(4096)
			else:
				return None
				
			if data:
				packet = dhcp_packet.DHCPPacket(data)
				
				if packet.isDHCPRequestPacket():
					threading.Thread(target=self._handleDHCPRequest, args=(packet, source_address)).start()
				elif packet.isDHCPDiscoverPacket():
					threading.Thread(target=self._handleDHCPDiscover, args=(packet, source_address)).start()
				elif packet.isDHCPInformPacket():
					threading.Thread(target=self._handleDHCPInform, args=(packet, source_address)).start()
				elif packet.isDHCPReleasePacket():
					threading.Thread(target=self._handleDHCPRelease, args=(packet, source_address)).start()
				elif packet.isDHCPDeclinePacket():
					threading.Thread(target=self._handleDHCPDecline, args=(packet, source_address)).start()
				elif packet.isDHCPLeaseQueryPacket():
					threading.Thread(target=self._handleDHCPLeaseQuery, args=(packet, source_address)).start()
				return packet
			return None
			
	def _sendDHCPPacketTo(self, packet, ip, port):
		return self._response_socket.sendto(packet.encodePacket(), (ip, port))
		
	# Server-side Handle methods
	def _handleDHCPDecline(self, packet, source_address):
		pass
		
	def _handleDHCPDiscover(self, packet, source_address):
		pass
		
	def _handleDHCPInform(self, packet, source_address):
		pass
		
	def _handleDHCPLeaseQuery(self, packet, source_address):
		pass
		
	def _handleDHCPRelease(self, packet, source_address):
		pass
		
	def _handleDHCPRequest(self, packet, source_address):
		pass
		
