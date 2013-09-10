# -*- encoding: utf-8 -*-
"""
pydhcplib module: dhcp_network

Purpose
=======
 Handles send/receive and internal routing for DHCP packets.
 
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
import platform
import select
import socket
import struct
import threading

from dhcp_types.packet import DHCPPacket

_ETH_P_SNAP = 0x0005 #Internal-only Ethernet-frame-grabbing
#Nothing should be addressible to the special response socket, but better to avoid wasting memory

class DHCPNetwork(object):
    """
    Handles internal packet-path-routing logic.
    """
    _server_address = None #The IP associated with this server
    _network_link = None #The I/O-handler
    
    def __init__(self, server_address, server_port, client_port, pxe_port=None, response_interface=None):
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
        self._network_link = _NetworkLink(server_address, server_port, client_port, pxe_port, response_interface)
        
    def _getNextDHCPPacket(self, timeout=60, packet_buffer=2048):
        """
        Blocks for up to C{timeout} seconds while waiting for a packet to
        arrive; if one does, a thread is spawned to process it.
        
        @type timeout: int
        @param timeout: The number of seconds to wait before returning.
        
        @rtype: tuple(2)
        @return: (received:bool, (address:basestring, port:int)|None), with received
            indicating whether a DHCP packet was received or not and the tuple
            reflecting the source of the received packet, if any.
        """
        (source_address, data) = self._network_link.getData()
        if data:
            packet = DHCPPacket(data)
            if packet.isDHCPPacket():
                pxe = active_socket == self._pxe_socket
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
                return (True, source_address)
        return (False, source_address)
        
    def _handleDHCPDecline(self, packet, source_address, pxe):
        """
        Processes a DECLINE packet.
        
        @type packet: L{dhcp_types.packet.DHCPPacket}
        @param packet: The packet to be processed.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        
    def _handleDHCPDiscover(self, packet, source_address, pxe):
        """
        Processes a DISCOVER packet.
        
        @type packet: L{dhcp_types.packet.DHCPPacket}
        @param packet: The packet to be processed.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        
    def _handleDHCPInform(self, packet, source_address, pxe):
        """
        Processes an INFORM packet.
        
        @type packet: L{dhcp_types.packet.DHCPPacket}
        @param packet: The packet to be processed.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        
    def _handleDHCPLeaseQuery(self, packet, source_address, pxe):
        """
        Processes a LEASEQUERY packet.
        
        @type packet: L{dhcp_types.packet.DHCPPacket}
        @param packet: The packet to be processed.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        
    def _handleDHCPRelease(self, packet, source_address):
        """
        Processes a RELEASE packet.
        
        @type packet: L{dhcp_types.packet.DHCPPacket}
        @param packet: The packet to be processed.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        """
        
    def _handleDHCPRequest(self, packet, source_address, pxe):
        """
        Processes a REQUEST packet.
        
        @type packet: L{dhcp_types.packet.DHCPPacket}
        @param packet: The packet to be processed.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        
    def _sendDHCPPacket(self, packet, ip, port, pxe):
        """
        Encodes and sends a DHCP packet to its destination.
        
        @type packet: L{dhcp_types.packet.DHCPPacket}
        @param packet: The packet to be sent.
        @type ip: basestring
        @param ip: The IP address to which the packet is to be sent.
        @type port: int
        @param port: The port to which the packet is to be addressed.
        @type pxe: bool
        @param pxe: True if the packet was received via the PXE port
        """
        packet_encoded = packet.encodePacket()

        # When responding to a relay, the packet will be unicast, so use
        # self._dhcp_socket so the source port will be 67. Some relays
        # will not relay when the source port is not 67. Or, if PXE is in
        # use, use that socket instead.
        #
        # Otherwise use self._response_socket because it has SO_BROADCAST.
        #
        # If self._dhcp_socket is anonymously bound, the two sockets will
        # actually be one and the same, so this change has no potentially
        # damaging effects.
        ip = str(ip)
        if not ip == '255.255.255.255':
            if pxe:
                return self._pxe_socket.sendto(packet_encoded, (ip, port))
            else:
                return self._dhcp_socket.sendto(packet_encoded, (ip, port))
        else:
            return self._response_socket.sendto(packet_encoded, (ip, port))
            
Packet:        
    response_mac = None #If set to something coerceable into a MAC, the packet will be sent to this MAC, rather than its default
    response_ip = None #If set to something coerceable into an IPv4, the packet will be sent to this IP, rather than its default
    response_port = None #If set to an integer, the packet will be sent to this port, rather than its default_l2
    
    
            
class _NetworkLink(object):
    """
    Handles network I/O.
    """
    _server_port = None #: The port on which DHCP servers and relays listen in this network.
    _client_port = None #: The port on which DHCP clients listen in this network.
    _responder_dhcp = None
    _responder_pxe = None
    _responder_broadcast = None
    _dhcp_socket = None #: The socket used to receive DHCP requests.
    _pxe_socket = None #: The socket used to receive PXE requests.
    _listening_sockets = None #: All sockets on which to listen for activity.
    
    def __init__(self, server_address, server_port, client_port, pxe_port, response_interface=None):
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
        self._server_port = server_port
        self._client_port = client_port
        
        (dhcp_socket, pxe_socket) = self._setupSockets(server_address, server_port, client_port, pxe_port)
        if pxe_socket:
            self._listening_sockets = (dhcp_socket, pxe_socket)
        else:
            self._listening_sockets = (dhcp_socket,)
            
        if response_interface:
            self._responder_dhcp = self._responder_pxe = self._responder_broadcast = _RawResponder()
        else:
            self._responder_dhcp = _Responder(dhcp_socket)
            self._responder_pxe = _Responder(pxe_socket)
            self._responder_broadcast = _Responder()
            
    def _setupSockets(self, server_port, pxe_port):
        dhcp_socket = pxe_socket = None
        try:
            dhcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if pxe_port:
                pxe_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error, msg:
            raise Exception('Unable to create socket: %(err)s' % {'err': str(msg),})
            
        try: 
            dhcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if pxe_socket:
                pxe_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except socket.error, msg :
            _logger.warn('Unable to set SO_REUSEADDR; multiple DHCP servers cannot be run in parallel: %(err)s' % {'err': str(msg),})
            
        if platform.system() != 'Linux':
            try: 
                dhcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                if pxe_port:
                    pxe_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except socket.error, msg :
                _logger.warn('Unable to set SO_REUSEPORT; multiple DHCP servers cannot be run in parallel: %(err)s' % {'err': str(msg),})
                
        try:
            dhcp_socket.bind(('', server_port))
            if pxe_port:
                pxe_socket.bind(('', pxe_port))
        except socket.error, e:
            raise Exception('Unable to bind sockets: %(error)s' % {
             'error': str(e),
            })
            
        return (dhcp_socket, pxe_socket)
        
    def getData(self, timeout, packet_buffer):
        active_sockets = select.select(self._listening_sockets, [], [], timeout)[0]
        if active_sockets:
            active_socket = active_sockets[0]
            (data, source_address) = active_socket.recvfrom(packet_buffer)
            if data:
                return (source_address, data)
        return (source_address, None)
        
    def sendData(self):
        pass
        
        
class _Responder(object):
    _socket = None
    
    def __init__(self, socket=None):
        if socket:
            self._socket = socket
        else:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            try:
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            except socket.error, e:
                raise Exception('Unable to set SO_BROADCAST: %(err)s' % {'err': e,})
            
            try:
                self._response_socket.bind((server_address or '', 0))
            except socket.error, e:
                raise Exception('Unable to bind socket: %(error)s' % {'error': e,})
                
    def send(self, packet, address, pxe, mac, client_ip):
        ip = port = None
        if address[0] in _IP_UNSPECIFIED_FILTER: #Broadcast source
            if packet.getOption('flags')[0] & 0b10000000: #Broadcast bit set; respond in kind
                ip = _IP_BROADCAST
            else: #The client wants to receive a response via unicast
                ip = packet.extractIPOrNone('yiaddr')
            port = self._client_port
        else: #Unicast source
            giaddr = packet.extractIPOrNone('giaddr')
            ip = address[0]
            if giaddr: #Relayed request.
                port = self._server_port
            else: #Request directly from client, routed or otherwise.
                if pxe:
                    ip = packet.extractIPOrNone('ciaddr') or ip
                    port = address[1] or self._client_port #BSD doesn't seem to preserve port information
                else:
                    port = self._client_port
                    
        return self._socket.sendto(packet_encoded, (ip, port))
        
class _RawResponder(_Responder):
    def __init__(self, response_interface):
        self._socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_SNAP))
        self._socket.bind((response_interface, _ETH_P_SNAP))
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 ** 12)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 ** 12)
        
    def _buildEthernetHeader(self, dest_mac):
        return (
         ''.join(chr(i) for i in dest_mac) +
         self._socket.getsockname()[4] +
         "\x08\x00", #IP payload-type
        )
        
    def send(self, packet, address, pxe, mac, client_ip):
        packet = self._buildEthernetHeader(mac)
        return self._socket.send(packet)
        
"""
Use self._response_socket for both DHCP and PXE responses, writing the source-port as appropriate

Try to move most of the dhcp.py send logic here, since it's largely packet-introspection and that's
all very generally applicable to DHCP server behaviour.

References:
    UDP header: 8 bytes (source: 16, destination: 16, length: 16, checksum: 16)
    The length includes the size of the header (8 bytes)
    Checksum, from pyip:
        def cksum(s):
            if len(s) & 1:
                s = s + '\0'
            words = array.array('h', s)
            sum = 0
            for word in words:
                sum = sum + (word & 0xffff)
            hi = sum >> 16
            lo = sum & 0xffff
            sum = hi + lo
            sum = sum + (sum >> 16)
            return (~sum) & 0xffff
            
        def _assemble(self, cksum=1):
            self.ulen = 8 + len(self.data)
            begin = struct.pack('HHH', self.sport, self.dport, self.ulen)
            packet = begin + '\000\000' + self.data
            if cksum:
                self.sum = inetutils.cksum(packet)
                packet = begin + struct.pack('H', self.sum) + self.data
            self.__packet = inetutils.udph2net(packet)
            return self.__packet
            
            
            
'''
    Raw sockets on Linux
     
    Silver Moon (m00n.silv3r@gmail.com)
'''
 
# some imports
import socket, sys
from struct import *
 
# checksum functions needed for calculation checksum
def checksum(msg):
    s = 0
     
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w
     
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);
     
    #complement and mask to 4 byte short
    s = ~s & 0xffff
     
    return s
 
#create a raw socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
 
# tell kernel not to put in headers, since we are providing it, when using IPPROTO_RAW this is not necessary
# s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
     
# now start constructing the packet
packet = '';
 
source_ip = '192.168.1.101'
dest_ip = '192.168.1.1' # or socket.gethostbyname('www.google.com')
 
# ip header fields
ip_ihl = 5
ip_ver = 4
ip_tos = 0
ip_tot_len = 0  # kernel will fill the correct total length
ip_id = 54321   #Id of this packet
ip_frag_off = 0
ip_ttl = 255
ip_proto = socket.IPPROTO_TCP
ip_check = 0    # kernel will fill the correct checksum
ip_saddr = socket.inet_aton ( source_ip )   #Spoof the source ip address if you want to
ip_daddr = socket.inet_aton ( dest_ip )
 
ip_ihl_ver = (ip_ver << 4) + ip_ihl
 
# the ! in the pack format string means network order
ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
 
# tcp header fields
tcp_source = 1234   # source port
tcp_dest = 80   # destination port
tcp_seq = 454
tcp_ack_seq = 0
tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
#tcp flags
tcp_fin = 0
tcp_syn = 1
tcp_rst = 0
tcp_psh = 0
tcp_ack = 0
tcp_urg = 0
tcp_window = socket.htons (5840)    #   maximum allowed window size
tcp_check = 0
tcp_urg_ptr = 0
 
tcp_offset_res = (tcp_doff << 4) + 0
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
 
# the ! in the pack format string means network order
tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)
 
user_data = 'Hello, how are you'
 
# pseudo header fields
source_address = socket.inet_aton( source_ip )
dest_address = socket.inet_aton(dest_ip)
placeholder = 0
protocol = socket.IPPROTO_TCP
tcp_length = len(tcp_header) + len(user_data)
 
psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
psh = psh + tcp_header + user_data;
 
tcp_check = checksum(psh)
#print tcp_checksum
 
# make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)
 
# final full packet - syn packets dont have any data
packet = ip_header + tcp_header + user_data
 
#Send the packet finally - the port specified has no effect
s.sendto(packet, (dest_ip , 0 ))    # put this in a loop if you want to flood the target

"""

