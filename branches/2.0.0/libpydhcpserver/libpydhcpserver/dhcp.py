# -*- encoding: utf-8 -*-
"""
libpydhcpserver.dhcp_network
============================
Handles send/receive and internal routing for DHCP packets.

Legal
-----
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

(C) Neil Tallim, 2013 <flan@uguu.ca>
(C) Matthew Boedicker, 2011 <matthewm@boedicker.org>
(C) Mathieu Ignacio, 2008 <mignacio@april.org>
"""
import collections
import platform
import select
import socket
import threading

from dhcp_types.ipv4 import IPv4
from dhcp_types.mac import MAC
from dhcp_types.packet import DHCPPacket

#IP constants
_IP_GLOB = IPv4('0.0.0.0')
_IP_BROADCAST = IPv4('255.255.255.255')
IP_UNSPECIFIED_FILTER = (_IP_GLOB, _IP_BROADCAST, None)

_ETH_P_SNAP = 0x0005 #Internal-only Ethernet-frame-grabbing
#Nothing should be addressible to the special response socket, but better to avoid wasting memory

Address = collections.namedtuple("Address", ('ip', 'port'))
"""
ip is an IPv4
port is an integer
"""

class DHCPServer(object):
    """
    Handles internal packet-path-routing logic.
    """
    _server_address = None #The IP associated with this server
    _network_link = None #The I/O-handler
    
    def __init__(self, server_address, server_port, client_port, pxe_port=None, response_interface=None, response_interface_qtags=None):
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
        self._network_link = _NetworkLink(server_address, server_port, client_port, pxe_port, response_interface, response_interface_qtags=response_interface_qtags)
        
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
        (source_address, data, pxe) = self._network_link.getData(timeout=timeout, packet_buffer=packet_buffer)
        if data:
            packet = DHCPPacket(data)
            if packet.isDHCPPacket():
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
        
    def _sendDHCPPacket(self, packet, address, pxe, mac, client_ip):
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
        return self._network_link.sendData(packet, address, pxe, mac, client_ip)
        
        
class _NetworkLink(object):
    """
    Handles network I/O.
    """
    _client_port = None
    _server_port = None
    _pxe_port = None
    _pxe_socket = None
    _responder_dhcp = None
    _responder_pxe = None
    _responder_broadcast = None
    _listening_sockets = None #: All sockets on which to listen for activity.
    _unicast_discover_supported = False
    
    def __init__(self, server_address, server_port, client_port, pxe_port, response_interface=None, response_interface_qtags=None):
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
        self._client_port = client_port
        self._server_port = server_port
        self._pxe_port = pxe_port
        
        (dhcp_socket, pxe_socket) = self._setupListeningSockets(server_port, pxe_port)
        if pxe_socket:
            self._listening_sockets = (dhcp_socket, pxe_socket)
            self._pxe_socket = pxe_socket
        else:
            self._listening_sockets = (dhcp_socket,)
            
        self._responder_dhcp = _L3Responder(socketobj=dhcp_socket)
        self._responder_pxe = _L3Responder(socketobj=pxe_socket)
        if response_interface:
            try:
                self._responder_broadcast = _L2Responder_AF_PACKET(server_address, response_interface, qtags=response_interface_qtags)
            except Exception:
                try:
                    self._responder_broadcast = _L2Responder_pcap(server_address, response_interface, qtags=response_interface_qtags)
                except Exception, e:
                    import errno
                    raise EnvironmentError(errno.ELIBACC, "Raw response-socket requested on %(interface)s, but neither AF_PACKET/PF_PACKET nor libpcap are available" % {'interface': response_interface,})
            self._unicast_discover_supported = True
        else:
            self._responder_broadcast = _L3Responder(server_address=server_address)
            
    def _setupListeningSockets(self, server_port, pxe_port):
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
        except socket.error, msg:
            import warnings
            warnings.warn('Unable to set SO_REUSEADDR; multiple DHCP servers cannot be run in parallel: %(err)s' % {'err': str(msg),})
            
        if platform.system() != 'Linux':
            try: 
                dhcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                if pxe_port:
                    pxe_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except socket.error, msg:
                import warnings
                warnings.warn('Unable to set SO_REUSEPORT; multiple DHCP servers cannot be run in parallel: %(err)s' % {'err': str(msg),})
                
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
        pxe = False
        active_sockets = select.select(self._listening_sockets, [], [], timeout)[0]
        if active_sockets:
            active_socket = active_sockets[0]
            pxe = active_socket == self._pxe_socket
            (data, source_address) = active_socket.recvfrom(packet_buffer)
            if data:
                return (Address(IPv4(source_address[0]), source_address[1]), data, pxe)
        return (None, None, False)
        
    def sendData(self, packet, address, pxe, mac, client_ip):
        ip = None
        port = self._client_port
        source_port = self._server_port
        responder = self._responder_dhcp
        if address[0] in IP_UNSPECIFIED_FILTER: #Broadcast source; this is never valid for PXE
            if (not self._unicast_discover_supported or #All responses have to be via broadcast
                packet.getOption('flags')[0] & 0b10000000): #Broadcast bit set; respond in kind 
                ip = _IP_BROADCAST
            else: #The client wants unicast and this host can handle it
                ip = packet.extractIPOrNone('yiaddr')
            responder = self._responder_broadcast
        else: #Unicast source
            giaddr = packet.extractIPOrNone('giaddr')
            ip = address[0]
            if giaddr: #Relayed request.
                port = self._server_port
            else: #Request directly from client, routed or otherwise.
                if pxe:
                    ip = packet.extractIPOrNone('ciaddr') or ip
                    port = address[1] or self._pxe_port #BSD doesn't seem to preserve port information
                    source_port = self._pxe_port
                    responder = self._responder_pxe
                    
        return responder.send(packet, mac, ip, port, source_port=source_port)
        
class _Responder(object):
    _socket = None #The socket used for responses; its semantics vary by subclass
    
    def _setBroadcastBit(self, packet, state):
        flags = packet.getOption('flags')
        old_state = bool(flags[0] & 0b10000000)
        if state:
            flags[0] |= 0b10000000
        else:
            flags[0] &= 0b01111111
        packet.setOption('flags', flags)
        return old_state
        
    def send(self, packet, mac, ip, port, *args, **kwargs):
        old_broadcast_bit = self._setBroadcastBit(packet, ip == _IP_BROADCAST)
        
        #Perform any packet-specific rewriting
        mac = packet.response_mac or mac
        if not old_broadcast_bit:
            ip = packet.response_ip or ip
        port = packet.response_port or port
        if packet.response_source_port is not None:
            kwargs['source_port'] = packet.response_source_port
            
        bytes_sent = self._send(packet, mac, ip, port, *args, **kwargs)
        self._setBroadcastBit(packet, old_broadcast_bit) #Restore the broadcast bit, in case the packet needs to be used for something else
        return (bytes_sent, ip, port)
    def _send(self, packet, mac, ip, port, *args, **kwargs):
        raise NotImplementedError("_send() must be implemented in subclasses")
        
class _L3Responder(_Responder):
    def __init__(self, socketobj=None, server_address=None):
        if socketobj:
            self._socket = socketobj
        else:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            try:
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            except socket.error, e:
                raise Exception('Unable to set SO_BROADCAST: %(err)s' % {'err': e,})
            
            try:
                self._socket.bind((server_address or '', 0))
            except socket.error, e:
                raise Exception('Unable to bind socket: %(error)s' % {'error': e,})
                
    def _send(self, packet, mac, ip, port, *args, **kwargs):
        return self._socket.sendto(packet.encodePacket(), (str(ip), port))
        
class _L2Responder(_Responder):
    _ethernet_id = None #The source MAC and Ethernet payload-type (and qtags, if applicable)
    _server_address = None #The server's IP
    
    __array = None
    __pack = None
    
    def __init__(self, server_address, mac, qtags=None):
        import struct
        self.__pack = struct.pack
        import array
        self.__array = array.array
        
        self._server_address = socket.inet_aton(str(server_address))
        ethernet_id = [self._socket.getsockname()[4],] #Source MAC
        if qtags:
            for (pcp, dei, vid) in qtags:
                ethernet_id.append("\x81\x00") #qtag payload-type
                qtag_value = pcp << 13 #Priority-code-point (0-7)
                qtag_value += int(dei) << 12 #Drop-eligible-indicator
                qtag_value += vid #vlan-identifier
                ethernet_id.append(self.__pack('!H', qtag_value))
        ethernet_id.append("\x08\x00") #IP payload-type
        self._ethernet_id = ''.join(ethernet_id)
        
    def _checksum(self, data):
        if sum(len(i) for i in data) & 1:
            data.append('\0')
            
        words = self.__array('h', ''.join(data))
        checksum = 0
        for word in words:
            checksum += word & 0xffff
        hi = checksum >> 16
        low = checksum & 0xffff
        checksum = hi + low
        checksum += (checksum >> 16)
        return ~checksum & 0xffff
        
    def _ipChecksum(self, ip_prefix, ip_destination):
        return self._checksum([
         ip_prefix,
         '\0\0', #Empty checksum field
         self._server_address,
         ip_destination,
        ])
        
    def _udpChecksum(self, ip_destination, udp_addressing, udp_length, packet):
        return self._checksum([
         self._server_address,
         ip_destination,
         '\0\x11', #UDP spec padding and protocol
         udp_length,
         udp_addressing,
         udp_length,
         '\0\0', #Dummy UDP checksum
         packet,
        ])
        
    def _assemblePacket(self, packet, mac, ip, port, source_port):
        binary = []
        ip = str(ip)
        
        #<> Ethernet header
        if ip == _IP_BROADCAST:
            binary.append('\xff\xff\xff\xff\xff\xff') #Broadcast MAC
        else:
            binary.append(''.join(chr(i) for i in mac)) #Destination MAC
        binary.append(self._ethernet_id) #Source MAC and Ethernet payload-type
        
        #<> Prepare packet data for transmission and checksumming
        packet = packet.encodePacket()
        packet_len = len(packet)
        
        #<> IP header
        binary.append(self.__pack("!BBHHHBB",
         69, #IPv4 + length=5
         0, #DSCP/ECN aren't relevant
         28 + packet_len, #The UDP and packet lengths in bytes
         0, #ID, which is always 0 because we're the origin
         packet_len <= 560 and 0b0100000000000000 or 0, #Flags and fragmentation
         128, #Make the default TTL sane, but not maximum
         0x11, #Protocol=UDP
        ))
        ip_destination = socket.inet_aton(str(ip))
        binary.extend((
         self.__pack("<H", self._ipChecksum(binary[-1], ip_destination)),
         self._server_address,
         ip_destination
        ))
        
        #<> UDP header
        binary.append(self.__pack("!HH", source_port, port))
        binary.append(self.__pack("!H", packet_len + 8)) #8 for the header itself
        binary.append(self.__pack("<H", self._udpChecksum(ip_destination, binary[-2], binary[-1], packet)))
        
        #<> Payload
        binary.append(packet)
        
        return ''.join(binary)
        
    def _send(self, packet, mac, ip, port, source_port=0, *args, **kwargs):
        binary_packet = self._assemblePacket(packet, mac, ip, port, source_port)
        return self._send_(binary_packet)
        
class _L2Responder_AF_PACKET(_L2Responder):
    def __init__(self, server_address, response_interface, qtags=None):
        socket_type = ((hasattr(socket, 'AF_PACKET') and socket.AF_PACKET) or (hasattr(socket, 'PF_PACKET') and socket.PF_PACKET))
        if not socket_type:
            raise Exception("Neither AF_PACKET nor PF_PACKET found")
        self._socket = socket.socket(socket_type, socket.SOCK_RAW, socket.htons(_ETH_P_SNAP))
        self._socket.bind((response_interface, _ETH_P_SNAP))
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 ** 12)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 ** 12)

        mac = self._socket.getsockname()[4]        
        _L2Responder.__init__(self, server_address, mac, qtags=qtags)

    def _send_(self, packet):
        return self._socket.send(packet)
        
class _L2Responder_pcap(_L2Responder):
    __c_int = None
    
    _inject = None
    
    def __init__(self, server_address, response_interface, qtags=None):
        import ctypes
        self.__c_int = ctypes.c_int
        import ctypes.util
        
        pcap = ctypes.util.find_library('pcap')
        if not pcap:
            raise Exception("libpcap not found")
        pcap = ctypes.cdll.LoadLibrary(pcap)
        
        errbuf = ctypes.create_string_buffer(256)
        self._socket = pcap.pcap_open_live(response_interface, ctypes.c_int(0), ctypes.c_int(0), ctypes.c_int(0), errbuf)
        if not self._socket:
            import errno
            raise IOError(errno.EACCES, errbuf.value)
        elif errbuf.value:
            import warnings
            warnings.warn(errbuf.value)
            
        #Ultra-hackish, but mostly portable, means of getting the MAC address for the interface
        import subprocess
        import re
        if platform.system() == 'Linux':
            command = ('/sbin/ip', 'link', 'show', response_interface)
        else:
            command = ('/sbin/ifconfig', response_interface)
        ifconfig_output = subprocess.check_output(command)
        m = re.search(r'\b(?P<mac>(?:[0-9A-Fa-f]{2}:){5}(?:[0-9A-Fa-f]{2}))\b', ifconfig_output)
        if not m:
            pcap.pcap_close(self._socket)
            raise Exception("Unable to determine MAC of %(interface)s using... ifconfig... Yes, really; someone, please provide a better way!" % {
             'interface': response_interface,
            })
        mac = ''.join(chr(i) for i in MAC(m.group('mac')))
        #End of hackery
        _L2Responder.__init__(self, server_address, mac, qtags=qtags)
        
        #The "send" function for the socket
        self._inject = pcap.pcap_inject
        
    def _send_(self, packet):
        return self._inject(self._socket, packet, self.__c_int(len(packet)))
        
