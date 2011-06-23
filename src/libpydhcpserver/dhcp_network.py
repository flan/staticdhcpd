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
 
 (C) Neil Tallim, 2011 <red.hamsterx@gmail.com>
 (C) Matthew Boedicker, 2011 <matthewm@boedicker.org>
 (C) Mathieu Ignacio, 2008 <mignacio@april.org>
"""
import select
import socket
import threading

import dhcp_packet

class DHCPNetwork(object):
    """
    Handles the actual network I/O and internal packet-path-routing logic.
    """
    _server_address = None #: The IP address of the DHCP service.
    _server_port = None #: The port on which DHCP servers and relays listen in this network.
    _client_port = None #: The port on which DHCP clients listen in this network.
    _pxe_port = None #: The port on which DHCP servers listen for PXE traffic in this network.
    _dhcp_socket = None #: The socket used to receive DHCP requests.
    _response_socket = None #: The socket used to send DHCP responses. Necessary because of how Linux handles broadcast.
    _pxe_socket = None #: The socket used to receive PXE requests.
    
    def __init__(self, server_address, server_port, client_port, pxe_port):
        """
        Sets up the DHCP network infrastructure.
        
        @type server_address: basestring
        @param server_address: The IP address on which to run the DHCP service.
        @type server_port: int
        @param server_port: The port on which DHCP servers and relays listen in this network.
        @type client_port: int
        @param client_port: The port on which DHCP clients listen in this network.
        @type pxe_port: int|NoneType
        @param pxe_port: The port on which DHCP servers listen for PXE traffic in this network.
        
        @raise Exception: A problem occurred during setup.
        """
        self._server_address = server_address
        self._server_port = server_port
        self._client_port = client_port
        self._pxe_port = pxe_port
        
        self._createSocket()
        self._bindToAddress()
        
    def _bindToAddress(self):
        """
        Binds the server and response sockets so they may be used.
        
        @raise Exception: A problem occurred while binding the sockets.
        """
        try:
            if self._server_address:
                self._response_socket.bind((self._server_address, 0))
            self._dhcp_socket.bind(('', self._server_port))
            if self._pxe_port:
                self._pxe_socket.bind(('', self._pxe_port))
        except socket.error, e:
            raise Exception('Unable to bind sockets: %(error)s' % {
             'error': str(e),
            })
            
    def _createSocket(self):
        """
        Creates and configures the server and response sockets.
        
        @raise Exception: A socket was in use or the OS doesn't support proper
            broadcast or reuse flags.
        """
        try:
            self._dhcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if self._server_address:
                self._response_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                self._response_socket = self._dhcp_socket
            if self._pxe_port:
                self._pxe_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error, msg:
            raise Exception('Unable to create socket: %(err)s' % {'err': str(msg),})
            
        try:
            self._response_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except socket.error, msg:
            raise Exception('Unable to set SO_BROADCAST: %(err)s' % {'err': str(msg),})
            
        try: 
            self._dhcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if self._pxe_socket:
                self._pxe_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except socket.error, msg :
            raise Exception('Unable to set SO_REUSEADDR: %(err)s' % {'err': str(msg),})
            
    def _getNextDHCPPacket(self, timeout=60):
        """
        Blocks for up to C{timeout} seconds while waiting for a packet to
        arrive; if one does, a thread is spawned to process it.
        
        @type timeout: int
        @param timeout: The number of seconds to wait before returning.
        
        @rtype: bool
        @return: True if something was received; False otherwise.
        """
        active_sockets = select.select([self._dhcp_socket], [], [], timeout)[0]
        if active_sockets:
            (data, source_address) = active_sockets[0].recvfrom(4096)
            if data:
                packet = dhcp_packet.DHCPPacket(data)
                if packet.isDHCPPacket():
                    pxe = source_address[1] == self._pxe_port
                    if packet.isDHCPRequestPacket():
                        threading.Thread(target=self._handleDHCPRequest, args=(packet, source_address, pxe)).start()
                    elif packet.isDHCPDiscoverPacket():
                        threading.Thread(target=self._handleDHCPDiscover, args=(packet, source_address, pxe)).start()
                    elif packet.isDHCPInformPacket():
                        threading.Thread(target=self._handleDHCPInform, args=(packet, source_address, pxe)).start()
                    elif packet.isDHCPReleasePacket():
                        threading.Thread(target=self._handleDHCPRelease, args=(packet, source_address, pxe)).start()
                    elif packet.isDHCPDeclinePacket():
                        threading.Thread(target=self._handleDHCPDecline, args=(packet, source_address, pxe)).start()
                    elif packet.isDHCPLeaseQueryPacket():
                        threading.Thread(target=self._handleDHCPLeaseQuery, args=(packet, source_address, pxe)).start()
                    return True
        return False
        
    def _handleDHCPDecline(self, packet, source_address, pxe):
        """
        Processes a DECLINE packet.
        
        @type packet: L{dhcp_packet.DHCPPacket}
        @param packet: The packet to be processed.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        pass
        
    def _handleDHCPDiscover(self, packet, source_address, pxe):
        """
        Processes a DISCOVER packet.
        
        @type packet: L{dhcp_packet.DHCPPacket}
        @param packet: The packet to be processed.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        pass
        
    def _handleDHCPInform(self, packet, source_address, pxe):
        """
        Processes an INFORM packet.
        
        @type packet: L{dhcp_packet.DHCPPacket}
        @param packet: The packet to be processed.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        pass
        
    def _handleDHCPLeaseQuery(self, packet, source_address, pxe):
        """
        Processes a LEASEQUERY packet.
        
        @type packet: L{dhcp_packet.DHCPPacket}
        @param packet: The packet to be processed.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        pass
        
    def _handleDHCPRelease(self, packet, source_address):
        """
        Processes a RELEASE packet.
        
        @type packet: L{dhcp_packet.DHCPPacket}
        @param packet: The packet to be processed.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        """
        pass
        
    def _handleDHCPRequest(self, packet, source_address, pxe):
        """
        Processes a REQUEST packet.
        
        @type packet: L{dhcp_packet.DHCPPacket}
        @param packet: The packet to be processed.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        pass
        
    def _sendDHCPPacketTo(self, packet, ip, port):
        """
        Encodes and sends a DHCP packet to its destination.
        
        @type packet: L{dhcp_packet.DHCPPacket}
        @param packet: The packet to be sent.
        @type ip: basestring
        @param ip: The IP address to which the packet is to be sent.
        @type port: int
        @param port: The port to which the packet is to be addressed.
        """
        packet_encoded = packet.encodePacket()

        # When responding to a relay, the packet will be unicast, so use
        # self._dhcp_socket so the source port will be 67. Some relays
        # will not relay when the source port is not 67.
        #
        # Otherwise use self._response_socket because it has SO_BROADCAST.
        #
        # If self._dhcp_socket is anonymously bound, the two sockets will
        # actually be one and the same, so this change has no potentially
        # damaging effects.
        if not ip == '255.255.255.255':
            return self._dhcp_socket.sendto(packet_encoded, (ip, port))
        else:
            return self._response_socket.sendto(packet_encoded, (ip, port))
            
