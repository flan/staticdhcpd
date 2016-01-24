# -*- encoding: utf-8 -*-
"""
libpydhcpserver.dhcp
====================
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

(C) Neil Tallim, 2014 <flan@uguu.ca>
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
from dhcp_types.packet import (DHCPPacket, FLAGBIT_BROADCAST)
from dhcp_types.constants import (
    FIELD_CIADDR, FIELD_YIADDR, FIELD_SIADDR, FIELD_GIADDR,
)

#IP constants
_IP_GLOB = IPv4('0.0.0.0') #: The internal "everything" address.
_IP_BROADCAST = IPv4('255.255.255.255') #: The broadcast address.
IP_UNSPECIFIED_FILTER = (_IP_GLOB, _IP_BROADCAST, None) #: A tuple of addresses that reflect non-unicast targets.

_ETH_P_SNAP = 0x0005
"""
Internal-only Ethernet-frame-grabbing for Linux.

Nothing should be addressable to the special response socket, but better to avoid wasting memory.
"""

_SO_BINDTODEVICE = 25 #Assume the most common Linux value by default
"""
The value for `SO_BINDTODEVICE` on the current platform; for BSD and other
UNIXes, `IP_RECVIF` is used instead, but it has the same usage semantics.
"""
if platform.system() == 'Linux':
    if hasattr(socket, 'SO_BINDTODEVICE'):
        _SO_BINDTODEVICE = socket.SO_BINDTODEVICE
    elif platform.machine() == 'sparc':
        _SO_BINDTODEVICE = 0x0d
    elif platform.machine() == 'parisc':
        _SO_BINDTODEVICE = 0x4019
else: #Assume BSD/OS X
   _SO_BINDTODEVICE = 20 #IP_RECVIF as defined in FreeBSD

Address = collections.namedtuple("Address", ('ip', 'port'))
"""
An inet layer-3 address.

.. py:attribute:: ip

    An :class:`IPv4 <dhcp_types.ipv4.IPv4>` address

.. py:attribute:: port

    A numeric port value.
"""

class DHCPServer(object):
    """
    Handles internal packet-path-routing logic.
    """
    _server_address = None #: The IP associated with this server.
    _network_link = None #: The I/O-handler; you don't want to touch this.

    def __init__(self, server_address, server_port, client_port, pxe_port=None, response_interface=None, response_interface_qtags=None):
        """
        Sets up the DHCP network infrastructure.

        :param server_address: The IP address on which to run the DHCP service.
        :type server_address: :class:`IPv4 <dhcp_types.ipv4.IPv4>`
        :param int port: The port on which DHCP servers and relays listen in this network.
        :param int client_port: The port on which DHCP clients listen in this network.
        :param int pxe_port: The port on which DHCP servers listen for PXE traffic in this
            network; ``None`` to disable.
        :param str response_interface: The interface on which to provide raw packet support,
            like ``"eth0"``, or ``None`` if not requested.
        :param sequence response_interface_qtags: Any qtags to insert into raw packets, in
            order of appearance. Definitions take the following form:
            (pcp:`0-7`, dei:``bool``, vid:`1-4094`)
        :except Exception: A problem occurred during setup.
        """
        self._server_address = server_address
        self._network_link = _NetworkLink(str(server_address), server_port, client_port, pxe_port, response_interface, response_interface_qtags=response_interface_qtags)

    def _getNextDHCPPacket(self, timeout=60, packet_buffer=2048):
        """
        Blocks for up to ``timeout`` seconds while waiting for a packet to
        arrive; if one does, a thread is spawned to process it.

        Have a thread blocking on this at all times; restart it immediately after it returns.

        :param int timeout: The number of seconds to wait before returning.
        :param int packet_buffer: The size of the buffer to use for receiving packets.
        :return tuple(2): (DHCP-packet-received:``bool``,
                          :class:`Address <dhcp.Address>` or ``None`` on
                          timeout)
        """
        (source_address, data, pxe) = self._network_link.getData(timeout=timeout, packet_buffer=packet_buffer)
        if data:
            try:
                packet = DHCPPacket(data=data)
            except ValueError:
                pass
            else:
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

        Override this with your own logic to handle DECLINEs.

        :param packet: The packet to be processed.
        :type packet: :class:`DHCPPacket <dhcp_types.packet.DHCPPacket>`
        :param source_address: The address from which the request was received.
        :type source_address: :class:`Address <dhcp.Address>`
        :param bool pxe: ``True`` if the packet was received on the PXE port.
        """

    def _handleDHCPDiscover(self, packet, source_address, pxe):
        """
        Processes a DISCOVER packet.

        Override this with your own logic to handle DISCOVERs.

        :param packet: The packet to be processed.
        :type packet: :class:`DHCPPacket <dhcp_types.packet.DHCPPacket>`
        :param source_address: The address from which the request was received.
        :type source_address: :class:`Address <dhcp.Address>`
        :param bool pxe: ``True`` if the packet was received on the PXE port.
        """

    def _handleDHCPInform(self, packet, source_address, pxe):
        """
        Processes an INFORM packet.

        Override this with your own logic to handle INFORMs.

        :param packet: The packet to be processed.
        :type packet: :class:`DHCPPacket <dhcp_types.packet.DHCPPacket>`
        :param source_address: The address from which the request was received.
        :type source_address: :class:`Address <dhcp.Address>`
        :param bool pxe: ``True`` if the packet was received on the PXE port.
        """

    def _handleDHCPLeaseQuery(self, packet, source_address, pxe):
        """
        Processes a LEASEQUERY packet.

        Override this with your own logic to handle LEASEQUERYs.

        :param packet: The packet to be processed.
        :type packet: :class:`DHCPPacket <dhcp_types.packet.DHCPPacket>`
        :param source_address: The address from which the request was received.
        :type source_address: :class:`Address <dhcp.Address>`
        :param bool pxe: ``True`` if the packet was received on the PXE port.
        """

    def _handleDHCPRelease(self, packet, source_address):
        """
        Processes a RELEASE packet.

        Override this with your own logic to handle RELEASEs.

        :param packet: The packet to be processed.
        :type packet: :class:`DHCPPacket <dhcp_types.packet.DHCPPacket>`
        :param source_address: The address from which the request was received.
        :type source_address: :class:`Address <dhcp.Address>`
        :param bool pxe: ``True`` if the packet was received on the PXE port.
        """

    def _handleDHCPRequest(self, packet, source_address, pxe):
        """
        Processes a REQUEST packet.

        Override this with your own logic to handle REQUESTs.

        :param packet: The packet to be processed.
        :type packet: :class:`DHCPPacket <dhcp_types.packet.DHCPPacket>`
        :param source_address: The address from which the request was received.
        :type source_address: :class:`Address <dhcp.Address>`
        :param bool pxe: ``True`` if the packet was received on the PXE port.
        """

    def _sendDHCPPacket(self, packet, source_address, pxe):
        """
        Encodes and sends a DHCP packet to its destination.

        **Important**: during this process, the packet may be modified, but
        will be restored to its initial state by the time this method returns.
        If any threadsafing is required, it must be handled in calling logic.

        :param packet: The packet to be processed.
        :type packet: :class:`DHCPPacket <dhcp_types.packet.DHCPPacket>`
        :param source_address: The address from which the request was received.
        :type source_address: :class:`Address <dhcp.Address>`
        :param bool pxe: ``True`` if the packet was received on the PXE port.
        :return int: The number of bytes transmitted.
        :except Exception: A problem occurred during serialisation or
            transmission.
        """
        return self._network_link.sendData(packet, source_address, pxe)


class _NetworkLink(object):
    """
    Handles network I/O.
    """
    _client_port = None #: The port on which clients expect to receive DHCP traffic.
    _server_port = None #: The port on which servers expect to receive DHCP traffic.
    _pxe_port = None #: The port on which PXE clients expect to receive traffic.
    _pxe_socket = None #: The internal socket to use for PXE traffic.
    _responder_dhcp = None #: The internal socket to use for responding to DHCP requests.
    _responder_pxe = None #: The internal socket to use for responding to PXE requests.
    _responder_broadcast = None #: The internal socket to use for responding to broadcast requests.
    _listening_sockets = None #: All sockets on which to listen for activity.
    _unicast_discover_supported = False #: Whether unicast responses to DISCOVERs are supported.

    def __init__(self, server_address, server_port, client_port, pxe_port, response_interface=None, response_interface_qtags=None):
        """
        Sets up the DHCP network infrastructure.

        :param str server_address: The IP address on which to run the DHCP service.
        :param int server_port: The port on which DHCP servers and relays listen in this network.
        :param int client_port: The port on which DHCP clients listen in this network.
        :param int|None pxe_port: The port on which DHCP servers listen for PXE traffic in this
            network.
        :param str|None response_interface: The interface on which to provide raw packet support,
            like 'eth0', or None if not requested.
        :param sequence|None response_interface_qtags: Any qtags to insert into raw packets, in
            order of appearance. Definitions take the following form:
            (pcp:`0-7`, dei:``bool``, vid:`1-4094`)
        :except Exception: A problem occurred during setup.
        """
        self._client_port = client_port
        self._server_port = server_port
        self._pxe_port = pxe_port

        #Create and bind unicast sockets
        (dhcp_socket, pxe_socket) = self._setupListeningSockets(server_port, pxe_port, server_address)
        if pxe_socket:
            self._listening_sockets = (dhcp_socket, pxe_socket)
            self._pxe_socket = pxe_socket
        else:
            self._listening_sockets = (dhcp_socket,)

        #Wrap the sockets with appropriate logic and set options
        self._responder_dhcp = _L3Responder(socketobj=dhcp_socket)
        self._responder_pxe = _L3Responder(socketobj=pxe_socket)
        #Either create a raw-response socket or a generic broadcast-response socket
        if response_interface:
            try:
                self._responder_broadcast = _L2Responder_AF_PACKET(server_address, response_interface, qtags=response_interface_qtags)
            except Exception:
                try:
                    self._responder_broadcast = _L2Responder_pcap(server_address, response_interface, qtags=response_interface_qtags)
                except Exception, e:
                    import errno
                    raise EnvironmentError(errno.ELIBACC, "Raw response-socket requested on %(interface)s, but neither AF_PACKET/PF_PACKET nor libpcap are available, or the interface does not exist" % {'interface': response_interface,})
            self._unicast_discover_supported = True
        else:
            self._responder_broadcast = _L3Responder(server_address=server_address)

    def _setupListeningSockets(self, server_port, pxe_port, server_address=None):
        """
        Creates and binds the listening sockets.

        :param int server_port: The port on which to listen for DHCP traffic.
        :param int pxe_port: The port on which to listen for PXE traffic.
        :param string server_address: The IP address to listen for DHCP traffic on
        :return tuple(2): The DHCP and PXE sockets, the latter of which may be ``None`` if not
            requested.
        :except socket.error: Sockets could not be created or bound.
        """
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

        if server_address:
            import ipv4_to_iface
            listen_interface = ipv4_to_iface.get_network_interface(server_address)
            try:
                dhcp_socket.setsockopt(socket.SOL_SOCKET, _SO_BINDTODEVICE, listen_interface)
            except socket.error, msg:
                raise OSError(msg.errno, 'Unable to listen only on %(listen_interface)s: %(err)s' % {
                 'listen_interface': listen_interface,
                 'err': msg.strerror,
                })

        return (dhcp_socket, pxe_socket)

    def getData(self, timeout, packet_buffer):
        """
        Runs `select()` over all relevant sockets, providing data if available.

        :param int timeout: The number of seconds to wait before returning.
        :param int packet_buffer: The size of the buffer to use for receiving packets.
        :return tuple(3):
            0. :class:`Address <dhcp.Address>` or ``None``: None if the timeout was reached.
            1. The received data as a ``str`` or ``None`` if the timeout was reached.
            2. A ``bool`` indicating whether the data was received via PXE.
        :except select.error: The `select()` operation did not complete gracefully.
        """
        pxe = False
        active_sockets = select.select(self._listening_sockets, [], [], timeout)[0]
        if active_sockets:
            active_socket = active_sockets[0]
            pxe = active_socket == self._pxe_socket
            (data, source_address) = active_socket.recvfrom(packet_buffer)
            if data:
                return (Address(IPv4(source_address[0]), source_address[1]), data, pxe)
        return (None, None, False)

    def sendData(self, packet, address, pxe):
        """
        Writes the packet to to appropriate socket, addressed to the appropriate recipient.

        :param packet: The packet to be written.
        :type packet: :class:`DHCPPacket <dhcp_types.packet.DHCPPacket>`
        :param address: The address from which the original packet was received.
        :type address: :class:`Address <dhcp.Address>`
        :param bool pxe: Whether the request was received via PXE.
        :return tuple(2):
            0. The number of bytes written to the network.
            1. The :class:`Address <dhcp.Address>` ultimately used.
        :except Exception: A problem occurred during serialisation or transmission.
        """
        ip = None
        relayed = False
        port = self._client_port
        source_port = self._server_port
        responder = self._responder_dhcp
        if address.ip in IP_UNSPECIFIED_FILTER: #Broadcast source; this is never valid for PXE
            if (not self._unicast_discover_supported #All responses have to be via broadcast
                or packet.getFlag(FLAGBIT_BROADCAST)): #Broadcast bit set; respond in kind
                ip = _IP_BROADCAST
            else: #The client wants unicast and this host can handle it
                #Try to get the client's address first, falling back to broadcast if missing
                ip = packet.extractIPOrNone(FIELD_YIADDR) or _IP_BROADCAST
            responder = self._responder_broadcast
        else: #Unicast source
            ip = address.ip
            relayed = bool(packet.extractIPOrNone(FIELD_GIADDR))
            if relayed: #Relayed request.
                port = self._server_port
            else: #Request directly from client, routed or otherwise.
                if pxe:
                    ip = packet.extractIPOrNone(FIELD_CIADDR) or ip
                    port = address.port or self._pxe_port #BSD doesn't seem to preserve port information
                    source_port = self._pxe_port
                    responder = self._responder_pxe

        return responder.send(packet, ip, port, relayed, source_port=source_port)

class _Responder(object):
    """
    A generic responder-template, which defines common logic.
    """
    def send(self, packet, ip, port, relayed, **kwargs):
        """
        Performs final sanity-checking and address manipulation, then submits the packet for
        transmission.

        :param packet: The packet to be written.
        :type packet: :class:`DHCPPacket <dhcp_types.packet.DHCPPacket>`
        :param ip: The address to which the packet should be sent.
        :type ip: :class:`IPv4 <dhcp_types.IPv4>`
        :param int port: The port to which the packet should be sent.
        :param bool relayed: ``True`` if the packet came from a relay.
        :param \*\*kwargs: Any technology-specific arguments.
        :return tuple(2):
            0. The number of bytes written to the network.
            1. The :class:`Address <dhcp.Address>` ultimately used.
        :except Exception: An error occurred during serialisation or transmission.
        """
        if relayed:
            broadcast_source = packet.extractIPOrNone(FIELD_CIADDR) in IP_UNSPECIFIED_FILTER
        else:
            broadcast_source = ip in IP_UNSPECIFIED_FILTER
        (broadcast_changed, original_was_broadcast) = packet.setFlag(FLAGBIT_BROADCAST, broadcast_source)

        #Perform any necessary packet-specific address-changes
        if not original_was_broadcast: #Unicast behaviour permitted; use the packet's IP override, if set
            ip = packet.response_ip or ip
        port = packet.response_port or port
        if packet.response_source_port is not None:
            kwargs['source_port'] = packet.response_source_port

        bytes_sent = self._send(packet, str(ip), port, **kwargs)
        if broadcast_changed: #Restore the broadcast bit, in case the packet needs to be used for something else
            packet.setFlag(FLAGBIT_BROADCAST, original_was_broadcast)
        return (bytes_sent, Address(IPv4(ip), port))

    def _send(self, packet, ip, port, **kwargs):
        """
        Handles technology-specific transmission; must be implemented by subclasses.

        :param packet: The packet to be written.
        :type packet: :class:`DHCPPacket <dhcp_types.packet.DHCPPacket>`
        :param ip: The address to which the packet should be sent.
        :type ip: :class:`IPv4 <dhcp_types.IPv4>`
        :param int port: The port to which the packet should be sent.
        :param \*\*kwargs: Any technology-specific arguments.
        :return int: The number of bytes written to the network.
        :except Exception: An error occurred during serialisation or transmission.
        """
        raise NotImplementedError("_send() must be implemented in subclasses")

class _L3Responder(_Responder):
    """
    Defines rules and logic needed to respond at layer 3.
    """
    _socket = None #: The socket used for responses.

    def __init__(self, socketobj=None, server_address=None):
        """
        Wraps an existing socket or creates an arbitrarily bound new socket with broadcast
        capabilities.

        :param socket.socket|None socketobj: The socket to be bound; if ``None``, a new one is
            created.
        :param str|None server_address: The address to which a new socket should be bound.
        :except Exception: Unable to bind a new socket.
        """
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

    def _send(self, packet, ip, port, **kwargs):
        """
        Serialises and sends the packet.

        :param packet: The packet to be written.
        :type packet: :class:`DHCPPacket <dhcp_types.packet.DHCPPacket>`
        :param str ip: The address to which the packet should be sent.
        :param int port: The port to which the packet should be sent.
        :param \*\*kwargs: Any technology-specific arguments.
        :return int: The number of bytes written to the network.
        :except Exception: An error occurred during serialisation or transmission.
        """
        return self._socket.sendto(packet.encodePacket(), (ip, port))

class _L2Responder(_Responder):
    """
    Defines rules and logic needed to respond at layer 2.
    """
    _ethernet_id = None #: The source MAC and Ethernet payload-type (and qtags, if applicable).
    _server_address = None #: The server's IP.

    #Locally cached module functions
    _array_ = None #: `array.array`
    _pack_ = None #: `struct.pack`

    def __init__(self, server_address, mac, qtags=None):
        """
        Constructs the Ethernet header for all L2 communication.

        :param str server_address: The server's IP as a dotted quad.
        :param str mac: The MAC of the responding interface, in network-byte order.
        :param sequence qtags: Any qtags to insert into raw packets, in order of appearance.
            Definitions take the following form: (pcp:`0-7`, dei:``bool``, vid:`1-4094`)
        """
        import struct
        self._pack_ = struct.pack
        import array
        self._array_ = array.array

        self._server_address = socket.inet_aton(str(server_address))
        ethernet_id = [mac,] #Source MAC
        if qtags:
            for (pcp, dei, vid) in qtags:
                ethernet_id.append("\x81\x00") #qtag payload-type
                qtag_value = pcp << 13 #Priority-code-point (0-7)
                qtag_value += int(dei) << 12 #Drop-eligible-indicator
                qtag_value += vid #vlan-identifier
                ethernet_id.append(self._pack('!H', qtag_value))
        ethernet_id.append("\x08\x00") #IP payload-type
        self._ethernet_id = ''.join(ethernet_id)

    def _checksum(self, data):
        """
        Computes the RFC768 checksum of ``data``.

        :param sequence data: The data to be checksummed.
        :return int: The data's checksum.
        """
        if sum(len(i) for i in data) & 1: #Odd
            checksum = sum(self._array_('H', ''.join(data)[:-1]))
            checksum += ord(data[-1][-1]) #Add the final byte
        else: #Even
            checksum = sum(self._array_('H', ''.join(data)))
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += (checksum >> 16)
        return ~checksum & 0xffff

    def _ipChecksum(self, ip_prefix, ip_destination):
        """
        Computes the checksum of the IPv4 header.

        :param str ip_prefix: The portion of the IPv4 header preceding the `checksum` field.
        :param str ip_destination: The destination address, in network-byte order.
        :return int: The IPv4 checksum.
        """
        return self._checksum([
         ip_prefix,
         '\0\0', #Empty checksum field
         self._server_address,
         ip_destination,
        ])

    def _udpChecksum(self, ip_destination, udp_addressing, udp_length, packet):
        """
        Computes the checksum of the UDP header and payload.

        :param str ip_destination: The destination address, in network-byte order.
        :param str udp_addressing: The UDP header's port section.
        :param str udp_length: The length of the UDP payload plus header.
        :param str packet: The serialised packet.
        :return int: The UDP checksum.
        """
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
        """
        Assembles the Ethernet, IPv4, and UDP headers, serialises the packet, and provides a
        complete Ethernet frame for injection into the network.

        :param packet: The packet to be written.
        :type packet: :class:`DHCPPacket <dhcp_types.packet.DHCPPacket>`
        :param mac: The MAC to which the packet is addressed.
        :type mac: :class:`MAC <dhcp_types.mac.MAC>`
        :param str ip: The IPv4 to which the packet is addressed, as a dotted quad.
        :param int port: The port to which the packet is addressed.
        :param int source_port: The port from which the packet is addressed.
        :return str: The complete binary packet.
        """
        binary = []

        #<> Ethernet header
        if _IP_BROADCAST == ip:
            binary.append('\xff\xff\xff\xff\xff\xff') #Broadcast MAC
        else:
            binary.append(''.join(chr(i) for i in mac)) #Destination MAC
        binary.append(self._ethernet_id) #Source MAC and Ethernet payload-type

        #<> Prepare packet data for transmission and checksumming
        binary_packet = packet.encodePacket()
        packet_len = len(binary_packet)

        #<> IP header
        binary.append(self._pack_("!BBHHHBB",
         69, #IPv4 + length=5
         0, #DSCP/ECN aren't relevant
         28 + packet_len, #The UDP and packet lengths in bytes
         0, #ID, which is always 0 because we're the origin
         packet_len <= 560 and 0b0100000000000000 or 0, #Flags and fragmentation
         128, #Make the default TTL sane, but not maximum
         0x11, #Protocol=UDP
        ))
        ip_destination = socket.inet_aton(ip)
        binary.extend((
         self._pack_("<H", self._ipChecksum(binary[-1], ip_destination)),
         self._server_address,
         ip_destination
        ))

        #<> UDP header
        binary.append(self._pack_("!HH", source_port, port))
        binary.append(self._pack_("!H", packet_len + 8)) #8 for the header itself
        binary.append(self._pack_("<H", self._udpChecksum(ip_destination, binary[-2], binary[-1], binary_packet)))

        #<> Payload
        binary.append(binary_packet)

        return ''.join(binary)

    def _send(self, packet, ip, port, source_port=0, **kwargs):
        """
        Serialises and sends the packet.

        :param packet: The packet to be written.
        :type packet: :class:`DHCPPacket <dhcp_types.packet.DHCPPacket>`
        :param str ip: The address to which the packet should be sent.
        :param int port: The port to which the packet should be sent.
        :param int source_port: The UDP port from which to claim the packet originated.
        :param \*\*kwargs: Any technology-specific arguments.
        :return int: The number of bytes written to the network.
        :except Exception: An error occurred during serialisation or transmission.
        """
        mac = (packet.response_mac and MAC(packet.response_mac)) or packet.getHardwareAddress()
        binary_packet = self._assemblePacket(packet, mac, ip, port, source_port)
        return self._send_(binary_packet)

class _L2Responder_AF_PACKET(_L2Responder):
    """
    A Linux-specific layer 2 responder that uses AF_PACKET/PF_PACKET.
    """
    _socket = None #: The socket used for responses.

    def __init__(self, server_address, response_interface, qtags=None):
        """
        Creates and configures a raw socket on an interface.

        :param str server_address: The server's IP as a dotted quad.
        :param str response_interface: The interface on which to provide raw packet support, like
            ``"eth0"``.
        :param sequence qtags: Any qtags to insert into raw packets, in order of appearance.
            Definitions take the following form: (pcp:`0-7`, dei:``bool``, vid:`1-4094`)
        :except socket.error: The socket could not be configured.
        """
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
        """
        Sends the packet.

        :param str packet: The packet to be written.
        :return int: The number of bytes written to the network.
        :except Exception: An error occurred during transmission.
        """
        return self._socket.send(packet)

class _L2Responder_pcap(_L2Responder):
    """
    A more general Unix-oriented layer 2 responder that uses libpcap.
    """
    _fd = None #: The file-descriptor of the socket used for responses.
    _inject = None #: The "send" function to invoke from libpcap.

    #Locally cached module functions
    _c_int_ = None #: `ctypes.c_int`

    def __init__(self, server_address, response_interface, qtags=None):
        """
        Creates and configures a raw socket on an interface.

        :param str server_address: The server's IP as a dotted quad.
        :param str response_interface: The interface on which to provide raw packet support, like
            ``"eth0"``.
        :param sequence qtags: Any qtags to insert into raw packets, in order of appearance.
            Definitions take the following form: (pcp:`0-7`, dei:``bool``, vid:`1-4094`)
        :except Exception: Interfacing with libpcap failed.
        """
        import ctypes
        self._c_int_ = ctypes.c_int
        import ctypes.util

        pcap = ctypes.util.find_library('pcap')
        if not pcap:
            raise Exception("libpcap not found")
        pcap = ctypes.cdll.LoadLibrary(pcap)

        errbuf = ctypes.create_string_buffer(256)
        self._fd = pcap.pcap_open_live(response_interface, ctypes.c_int(0), ctypes.c_int(0), ctypes.c_int(0), errbuf)
        if not self._fd:
            import errno
            raise IOError(errno.EACCES, errbuf.value)
        elif errbuf.value:
            import warnings
            warnings.warn(errbuf.value)

        try:
            mac = self._getMAC(response_interface)
        except Exception:
            pcap.pcap_close(self._fd)
            raise
        else:
            _L2Responder.__init__(self, server_address, mac, qtags=qtags)
        self._inject = pcap.pcap_inject

    def _getMAC(self, response_interface):
        """
        Mostly portable means of getting the MAC address for the interface.

        :param str response_interface: The interface on which to provide raw packet support, like
            ``"eth0"``.
        :return str: The MAC address, in network-byte order.
        :except Exception: The MAC could not be retrieved.
        """
        import subprocess
        import re
        if platform.system() == 'Linux':
            command = ('/sbin/ip', 'link', 'show', response_interface)
        else:
            command = ('/sbin/ifconfig', response_interface)
        ifconfig_output = subprocess.check_output(command)
        m = re.search(r'\b(?P<mac>(?:[0-9A-Fa-f]{2}:){5}(?:[0-9A-Fa-f]{2}))\b', ifconfig_output)
        if not m:
            raise Exception("Unable to determine MAC of %(interface)s" % {
             'interface': response_interface,
            })
        return ''.join(chr(i) for i in MAC(m.group('mac')))

    def _send_(self, packet):
        """
        Sends the packet.

        :param str packet: The packet to be written.
        :return int: The number of bytes written to the network.
        :except Exception: An error occurred during transmission.
        """
        return self._inject(self._fd, packet, self._c_int_(len(packet)))
