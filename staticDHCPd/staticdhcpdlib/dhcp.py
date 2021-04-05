# -*- encoding: utf-8 -*-
"""
staticdhcpdlib.dhcp
===================
Provides the DHCPd side of a staticDHCPd server.

Legal
-----
This file is part of staticDHCPd.
staticDHCPd is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

(C) Neil Tallim, 2021 <flan@uguu.ca>
"""
import collections
import logging
import select
import threading
import time
import traceback

from . import config
from . import statistics

import libpydhcpserver.dhcp
from libpydhcpserver.dhcp_types.ipv4 import IPv4
from libpydhcpserver.dhcp_types.mac import MAC

from .databases.generic import Definition

#Packet-type string-constants
_PACKET_TYPE_DECLINE = 'DECLINE'
_PACKET_TYPE_DISCOVER = 'DISCOVER'
_PACKET_TYPE_INFORM = 'INFORM'
_PACKET_TYPE_LEASEQUERY = 'LEASEQUERY'
_PACKET_TYPE_RELEASE = 'RELEASE'
_PACKET_TYPE_REQUEST = 'REQUEST'
_PACKET_TYPE_REQUEST_INIT_REBOOT = 'REQUEST:INIT-REBOOT'
_PACKET_TYPE_REQUEST_REBIND = 'REQUEST:REBIND'
_PACKET_TYPE_REQUEST_RENEW = 'REQUEST:RENEW'
_PACKET_TYPE_REQUEST_SELECTING = 'REQUEST:SELECTING'

#IP constants
_IP_REJECTED = '<nil>'

_logger = logging.getLogger('dhcp')

class _PacketWrapper(object):
    """
    Wraps a packet for the duration of a handler's operations, allowing for
    easy statistics aggregation, exception-handling, and reduction of in-line
    processing.
    """
    _server = None #: The server from which this packet was received.
    _packet_type = None #: The type of packet being wrapped.
    _original_packet = None #: The packet originally received.
    _discarded = True #: Whether the packet is in a discarded state.
    _start_time = None #: The time at which processing began.
    _associated_ip = None #: The client-ip associated with this request.
    _definition = None #: The definition associated with this request.

    valid = False #: Whether the packet passed basic sanity-tests.
    source_address = None #: The :class:`libpydhcpserver.dhcp.Address` of the packet's origin.
    packet = None #: The packet being wrapped.
    mac = None #: The MAC associated with the packet.
    ip = None #: The requested IP address associated with the packet, if any.
    sid = None #: The IP address of the server associated with the request, if any.
    ciaddr = None #: The IP address of the client, if any.
    giaddr = None #: The IP address of the gateway associated with the packet, if any.
    port = None #: The port on which the packet was received.

    def __init__(self, server, packet, packet_type, source_address, port):
        """
        Creates a new wrapper.

        :param :class:`_DHCPServer` server: The server associated with this
                                            packet.
        :param :class:`libpydhcpserver.dhcp_types.packet.DHCPPacket` packet: The
            packet being wrapped.
        :param basestring packet_type: The type of packet being wrapped.
        :param :class:`libpydhcpserver.dhcp.Address` source_address: The address
            of the source.
        :param int port: The port on which this packet arrived.
        """
        self._start_time = time.time()

        self._server = server
        self._packet_type = packet_type
        self.packet = packet
        self.source_address = source_address
        self.port = port

        self._extractInterestingFields()

    def __enter__(self):
        """
        Performs validation on the packet, storing the result in 'valid'.
        """
        self.announcePacket(verbosity=logging.DEBUG)

        try:
            self._evaluateSource()
            self._server.evaluateAbuse(self.mac)
        except _PacketSourceUnacceptable as e:
            _logger.warning("Request from {} ignored: {}".format(self.giaddr, e))
        except _PacketSourceIgnored as e:
            _logger.debug("Request from {} ignored: {}".format(self.mac, e))
        else:
            self.valid = True
            self._original_packet = self.packet.copy()

        return self

    def __exit__(self, type, value, tb):
        """
        Handles logging and notification in the event that processing terminated
        with an exception.

        Also ensures that statistical information is assembled and dispatched.
        """
        try:
            if isinstance(value, _PacketSourceBanlist):
                self._server.addToTempBanlist(self.mac, self._packet_type, str(value))
                return True
            elif isinstance(value, Exception):
                _logger.critical("Unable to handle {} from  {}:\n{}".format(
                    self._packet_type,
                    self.mac,
                    '\n'.join(traceback.format_exception(type, value, tb)),
                ))
                return True
        finally:
            if self._discarded:
                _logger.debug("Discarded packet of type {} from {}".format(self._packet_type, self.mac))
                
            time_taken = time.time() - self._start_time
            _logger.debug("{} request from {} processed in {:.4f} seconds".format(self._packet_type, self.mac, time_taken))

            if self._definition:
                ip = self._definition.ip
                subnet = self._definition.subnet
                serial = self._definition.serial
            else:
                subnet = serial = None
                ip = self._associated_ip
            statistics.emit(statistics.Statistics(
                self.source_address,
                self.mac, ip,
                subnet, serial,
                self._packet_type,
                time_taken, not self._discarded,
                self.port,
            ))

    def _extractInterestingFields(self):
        """
        Pulls commonly needed fields out of the packet, to avoid line-noise in
        the handling functions.
        """
        self.mac = self.packet.getHardwareAddress()
        self.ip = self.packet.extractIPOrNone("requested_ip_address")
        self.sid = self.packet.extractIPOrNone("server_identifier")
        self.ciaddr = self.packet.extractIPOrNone("ciaddr")
        self._associated_ip = self.ciaddr
        self.giaddr = self.packet.extractIPOrNone("giaddr")

    def _evaluateSource(self):
        """
        Determines whether the received packet belongs to a relayed request or
        not and decides whether it should be allowed based on policy.

        :except _PacketSourceUnacceptable: The packet was rejected.
        """
        if self.giaddr: #Relayed request.
            if not config.ALLOW_DHCP_RELAYS: #Ignore it.
                raise _PacketSourceUnacceptable("relay support not enabled")
            elif config.ALLOWED_DHCP_RELAYS and not self.giaddr in config.ALLOWED_DHCP_RELAYS:
                raise _PacketSourceUnacceptable("relay not authorised")
        elif not config.ALLOW_LOCAL_DHCP: #Local request, but denied.
            raise _PacketSourceUnacceptable("link-local traffic is not enabled")

    def announcePacket(self, ip=None, verbosity=logging.INFO):
        """
        Logs the occurance of the wrapped packet.

        :param basestring ip: The IP for which the request was sent, if known.
        :param int verbosity: A logging severity constant.
        """
        _logger.log(verbosity, '{type} from {mac}{ip}{sip} via port {port}'.format(
            type=self._packet_type,
            mac=self.mac,
            ip=(ip and (" for {}".format(ip)) or ''),
            sip=(
                self.source_address.ip not in libpydhcpserver.dhcp.IP_UNSPECIFIED_FILTER and
                " via {}:{}".format(self.source_address.ip, self.source_address.port) or
                ''
            ),
            port=self.port,
        ))

    def getType(self):
        """
        Provides the type of packet being processed.

        :return basestring: The type of packet being processed.
        """
        return self._packet_type

    def setType(self, packet_type):
        """
        Updates the type of packet being processed.

        :param basestring packet_type: The type of packet being processed.
        """
        self._packet_type = packet_type

    def markAddressed(self):
        """
        Indicate that the packet was processed to completion.
        """
        self._discarded = False

    def filterPacket(self, override_ip=False, override_ip_value=None):
        """
        A mechanism for allowing user-defined packet-filtering functionality.

        :param bool override_ip: True if the advertised client IP should be
                                 overridden with another value.
        :param :class:`libpydhcpserver.dhcp_types.packet.DHCPPacket` override_ip_value: The
            IP value to use for overriding.
        :return bool: True if the packet should be processed.
        :except _PacketSourceBanlist: The packet should be temporarily
                                        banlisted.
        """
        ip = self.ip
        if override_ip:
            ip = override_ip_value
            self._associated_ip = ip

        result = config.filterPacket(
            self.packet, self._packet_type,
            self.mac, ip, self.giaddr,
            self.port,
        )
        if result is None:
            raise _PacketSourceBanlist("filterPacket() returned None")
        return result

    def _loadDHCPPacket(self, definition, inform):
        """
        Sets option fields based on values returned from a database.

        :param :class:`databases.generic.Definition` definition: Parameters used
            to load the packet.
        :param bool inform: True if this is a response to an INFORM request,
            which will result in no IP being inserted into the response.
        """
        #Core parameters.
        if not inform:
            self.packet.setOption('yiaddr', definition.ip)
            self.packet.setOption(51, definition.lease_time)

        #Default gateway, subnet mask, and broadcast address.
        if definition.gateways:
            self.packet.setOption(3, definition.gateways)
        if definition.subnet_mask:
            self.packet.setOption(1, definition.subnet_mask)
        if definition.broadcast_address:
            self.packet.setOption(28, definition.broadcast_address)

        #Domain details.
        if definition.hostname:
            self.packet.setOption(12, definition.hostname)
        if definition.domain_name:
            self.packet.setOption(15, definition.domain_name)
        if definition.domain_name_servers:
            self.packet.setOption(6, definition.domain_name_servers)

        #NTP servers.
        if definition.ntp_servers:
            self.packet.setOption(42, definition.ntp_servers)

    def loadDHCPPacket(self, definition, inform=False):
        """
        Loads the packet with all normally required values, then passes it
        through user-defined scripting to further set fields as needed.

        :param :class:`databases.generic.Definition` definition: Parameters used
            to load the packet.
        :param bool inform: True if this is a response to an INFORM request.
        :return bool: True if processing should continue.
        """
        self._loadDHCPPacket(definition, inform)
        process = bool(config.loadDHCPPacket(
            self.packet, self._packet_type,
            self.mac, definition, self.giaddr,
            self.port,
            self._original_packet
        ))
        if not process:
            _logger.info('Ignoring {} from {} per loadDHCPPacket()'.format(self._packet_type, self.mac))
        return process

    def retrieveDefinition(self, override_ip=False, override_ip_value=None):
        """
        Queries the database and user-defined scripting to try to match the MAC
        to a "lease".

        :param bool override_ip: If True, `override_ip_value` will be used
            instead of the packet's `requested_ip_address` field.
        :param :class:`libpydhcpserver.dhcp_types.packet.DHCPPacket` override_ip_value: The
            IP value to use for overriding.
        :return :class:`databases.generic.Definition` definition: The associated
            definition; None if no "lease" is available.
        """
        ip = self.ip
        if override_ip:
            ip = override_ip_value
            self._associated_ip = ip

        definition = self._server.getDatabase().lookupMAC(self.mac) or config.handleUnknownMAC(
            self.packet, self._packet_type,
            self.mac, ip, self.giaddr,
            self.port,
        )

        #Allow for DBs to return multiple definitions that can then
        #be filtered based on the the additional information
        if definition and not isinstance(definition, Definition):
            _logger.debug('Multiple (count={}) definitions found'.format(len(definition)))
            self._definition = config.filterRetrievedDefinitions(
                definition, self.packet, self._packet_type, self.mac, ip,
                self.giaddr, self.port,
            )
        else:
            self._definition = definition or None

        return self._definition

def _dhcpHandler(packet_type):
    """
    A decorator to abstract away the wrapper boilerplate.

    :param basestring packet_type: The type of packet initially being processed.
    """
    def decorator(f):
        def wrappedHandler(self, packet, source_address, port):
            with _PacketWrapper(self, packet, packet_type, source_address, port) as wrapper:
                if not wrapper.valid:
                    return
                f(self, wrapper)
        return wrappedHandler
    return decorator



class _DHCPServer(libpydhcpserver.dhcp.DHCPServer):
    """
    The handler that responds to all received requests.
    """
    _lock = None #: A lock used to ensure synchronous access to internal structures.
    _database = None #: The database to use for retrieving lease definitions.
    _dhcp_actions = None #: The MACs and the number of actions each has performed, decremented by one each tick.
    _ignored_addresses = None #: A list of all MACs currently ignored, plus the time remaining until requests will be honoured again.

    def __init__(self, server_address, server_port, client_port, proxy_port, response_interface, response_interface_qtags, database):
        """
        Constructs the handler.

        :param basestring address: The IP of the interface from which responses
                                   are to be sent.
        :param int server_port: The port on which DHCP requests are expected to
                                arrive.
        :param int client_port: The port on which clients expect DHCP responses
                                to be sent.
        :param int proxy_port: The port on which to listen for proxyDHCP
                             requests, or None if ProxyDHCP support is disabled.
        :param :class:`databases.generic.Database` database: The database to use
            for retrieving lease definitions.
        :except Exception: A problem occurred while initializing the sockets
                           required to process messages.
        """
        self._lock = threading.Lock()
        self._database = database
        self._dhcp_actions = {}
        self._ignored_addresses = []

        libpydhcpserver.dhcp.DHCPServer.__init__(
            self, server_address, server_port, client_port, proxy_port,
            response_interface=response_interface,
            response_interface_qtags=response_interface_qtags,
        )

    @_dhcpHandler(_PACKET_TYPE_DECLINE)
    def _handleDHCPDecline(self, wrapper):
        """
        Informs the operator of a potential IP collision on the network.

        :param :class:`_PacketWrapper` wrapper: The wrapped packet to process.
        :except _PacketSourceBanlist: The MAC appears to be generating false
                                        information to disrupt the network.
        """
        if not wrapper.ip:
            raise _PacketSourceBanlist("conflicting IP was not specified")

        if not wrapper.sid:
            raise _PacketSourceBanlist("server-identifier was not specified")

        if wrapper.sid == self._server_address: #Rejected!
            if not wrapper.filterPacket(): return

            definition = wrapper.retrieveDefinition()
            if definition and definition.ip == wrapper.ip: #Known client.
                _logger.error("{type} from {mac} for {ip} on ({subnet}, {serial})".format(
                    type=wrapper.getType(),
                    ip=wrapper.ip,
                    mac=wrapper.mac,
                    subnet=definition.subnet,
                    serial=definition.serial,
                ))
                wrapper.markAddressed()
            elif definition:
                _logger.warning("{type} from {mac} for {ip}, but its assigned IP is {aip}".format(
                    type=wrapper.getType(),
                    mac=wrapper.mac,
                    ip=wrapper.ip,
                    aip=definition.ip,
                ))
            else:
                _logger.warning("{type} from {mac} for {ip}, but the MAC is unknown".format(
                    type=wrapper.getType(),
                    mac=wrapper.mac,
                    ip=wrapper.ip,
                ))

    @_dhcpHandler(_PACKET_TYPE_DISCOVER)
    def _handleDHCPDiscover(self, wrapper):
        """
        Evaluates a DISCOVER request from a client and determines whether an
        OFFER should be sent.

        :param :class:`_PacketWrapper` wrapper: The wrapped packet to process.
        :except _PacketSourceBanlist: The MAC can't be handled, but it also
                                        can't be NAKed, so reduce load.
        """
        if not wrapper.filterPacket(override_ip=True, override_ip_value=None): return
        wrapper.announcePacket()

        definition = wrapper.retrieveDefinition(override_ip=True, override_ip_value=None)
        if definition:
            if config.ENABLE_RAPIDCOMMIT and wrapper.packet.isOption(80):
                _logger.info("{} from {} requested rapid-commit".format(wrapper.getType(), wrapper.mac))
                wrapper.packet.transformToDHCPAckPacket()
                wrapper.packet.setOption(80, [])
            else:
                wrapper.packet.transformToDHCPOfferPacket()

            if wrapper.loadDHCPPacket(definition):
                self._emitDHCPPacket(
                    wrapper.packet, wrapper.source_address, wrapper.port,
                    wrapper.mac, definition.ip,
                )
                wrapper.markAddressed()
        else: #No support available for the MAC
            if config.AUTHORITATIVE:
                wrapper.packet.transformToDHCPNakPacket()
                self._emitDHCPPacket(
                    wrapper.packet, wrapper.source_address, wrapper.port,
                    wrapper.mac, _IP_REJECTED,
                )
                wrapper.markAddressed()
            else:
                raise _PacketSourceBanlist("unknown MAC and server is not authoritative; ignoring because rejection is impossible")

    @_dhcpHandler(_PACKET_TYPE_INFORM)
    def _handleDHCPInform(self, wrapper):
        """
        Evaluates an INFORM request from a client and determines whether an ACK
        should be sent.

        :param :class:`_PacketWrapper` wrapper: The wrapped packet to process.
        :except _PacketSourceBanlist: The MAC can't be handled, so reduce
                                        load.
        """
        if not wrapper.filterPacket(override_ip=True, override_ip_value=wrapper.ciaddr): return
        wrapper.announcePacket(ip=wrapper.ciaddr)

        if not wrapper.ciaddr:
            raise _PacketSourceBanlist("ciaddr was not specified")

        definition = wrapper.retrieveDefinition(override_ip=True, override_ip_value=wrapper.ciaddr)
        if definition:
            wrapper.packet.transformToDHCPAckPacket()
            if wrapper.loadDHCPPacket(definition, inform=True):
                self._emitDHCPPacket(
                    wrapper.packet, wrapper.source_address, wrapper.port,
                    wrapper.mac, wrapper.ciaddr or _IP_REJECTED,
                )
                wrapper.markAddressed()
        else:
            raise _PacketSourceBanlist("unknown MAC")

    @_dhcpHandler(_PACKET_TYPE_LEASEQUERY)
    def _handleDHCPLeaseQuery(self, wrapper):
        """
        Simply discards the packet; LEASEQUERY support was dropped in 1.7.0
        because the implementation was wrong.

        :param :class:`_PacketWrapper` wrapper: The wrapped packet to process.
        """
        if not wrapper.filterPacket(): return
        wrapper.announcePacket()

        #When reimplementing LEASEQUERY, create an alternative to the
        #'Definition' model and use that to transfer data through the wrapper
        #and handleUnknownMAC. Instead of retrieveDefinition(), it will be
        #retrieveLeaseDefinition() and handleUnknownMAC() will need to return
        #that as a third result. Its None still means it had nothing, though.

    @_dhcpHandler(_PACKET_TYPE_REQUEST)
    def _handleDHCPRequest(self, wrapper):
        """
        Evaluates a REQUEST request from a client and determines whether an ACK
        should be sent.

        :param :class:`_PacketWrapper` wrapper: The wrapped packet to process.
        """
        if wrapper.sid and not wrapper.ciaddr: #SELECTING
            self._handleDHCPRequest_SELECTING(wrapper)
        elif not wrapper.sid and not wrapper.ciaddr and wrapper.ip: #INIT-REBOOT
            self._handleDHCPRequest_INIT_REBOOT(wrapper)
        elif not wrapper.sid and wrapper.ciaddr and not wrapper.ip: #RENEWING or REBINDING
            self._handleDHCPRequest_RENEW_REBIND(wrapper)
        else:
            _logger.warning("{type} ({sid}|{ciaddr}|{ip}) from {mac} unhandled: packet not compliant with DHCP spec".format(
                type=wrapper.getType(),
                sid=wrapper.sid,
                ciaddr=wrapper.ciaddr,
                ip=wrapper.ip,
                mac=wrapper.mac,
            ))

    def _handleDHCPRequest_SELECTING(self, wrapper):
        """
        Evaluates a SELECTING REQUEST from a client and determines whether an
        ACK or NAK should be sent.

        :param :class:`_PacketWrapper` wrapper: The wrapped packet to process.
        """
        wrapper.setType(_PACKET_TYPE_REQUEST_SELECTING)
        if wrapper.sid == self._server_address: #Chosen!
            if not wrapper.filterPacket(): return
            wrapper.announcePacket(ip=wrapper.ip)

            definition = wrapper.retrieveDefinition()
            if definition and (not wrapper.ip or definition.ip == wrapper.ip):
                wrapper.packet.transformToDHCPAckPacket()
                if wrapper.loadDHCPPacket(definition):
                    self._emitDHCPPacket(
                        wrapper.packet, wrapper.source_address, wrapper.port,
                        wrapper.mac, wrapper.ip,
                    )
                    wrapper.markAddressed()
            else:
                wrapper.packet.transformToDHCPNakPacket()
                self._emitDHCPPacket(
                    wrapper.packet, wrapper.source_address, wrapper.port,
                    wrapper.mac, _IP_REJECTED,
                )
                wrapper.markAddressed()

    def _handleDHCPRequest_INIT_REBOOT(self, wrapper):
        """
        Evaluates and an INIT-REBOOT REQUEST from a client and determines
        whether an ACK or NAK should be sent.

        :param :class:`_PacketWrapper` wrapper: The wrapped packet to process.
        """
        wrapper.setType(_PACKET_TYPE_REQUEST_INIT_REBOOT)
        if not wrapper.filterPacket(): return
        wrapper.announcePacket(ip=wrapper.ip)

        definition = wrapper.retrieveDefinition()
        if definition and definition.ip == wrapper.ip:
            wrapper.packet.transformToDHCPAckPacket()
            if wrapper.loadDHCPPacket(definition):
                self._emitDHCPPacket(
                    wrapper.packet, wrapper.source_address, wrapper.port,
                    wrapper.mac, wrapper.ip,
                )
                wrapper.markAddressed()
        else:
            wrapper.packet.transformToDHCPNakPacket()
            self._emitDHCPPacket(
                wrapper.packet, wrapper.source_address, wrapper.port,
                wrapper.mac, wrapper.ip,
            )
            wrapper.markAddressed()

    def _handleDHCPRequest_RENEW_REBIND(self, wrapper):
        """
        Evaluates a RENEW or REBIND REQUEST from a client and determines whether
        an ACK or NAK should be sent.

        If policy forbids RENEW and REBIND operations, perhaps to prepare for a
        new configuration rollout, all such requests are NAKed immediately.

        :param :class:`_PacketWrapper` wrapper: The wrapped packet to process.
        """
        renew = wrapper.source_address.ip not in libpydhcpserver.dhcp.IP_UNSPECIFIED_FILTER
        wrapper.setType(renew and _PACKET_TYPE_REQUEST_RENEW or _PACKET_TYPE_REQUEST_REBIND)
        if not wrapper.filterPacket(): return
        wrapper.announcePacket(ip=wrapper.ip)

        if config.NAK_RENEWALS and (renew or config.AUTHORITATIVE):
            wrapper.packet.transformToDHCPNakPacket()
            self._emitDHCPPacket(
                wrapper.packet, wrapper.source_address, wrapper.port,
                wrapper.mac, _IP_REJECTED,
            )
            wrapper.markAddressed()
        else:
            definition = wrapper.retrieveDefinition()
            if definition and definition.ip == wrapper.ciaddr:
                wrapper.packet.transformToDHCPAckPacket()
                wrapper.packet.setOption('yiaddr', wrapper.ciaddr)
                if wrapper.loadDHCPPacket(definition):
                    self._emitDHCPPacket(
                        wrapper.packet,
                        libpydhcpserver.dhcp.Address(wrapper.ciaddr, 0), wrapper.port,
                        wrapper.mac, wrapper.ciaddr,
                    )
                    wrapper.markAddressed()
            elif definition or config.AUTHORITATIVE:
                if renew:
                    wrapper.packet.transformToDHCPNakPacket()
                    self._emitDHCPPacket(
                        wrapper.packet,
                        libpydhcpserver.dhcp.Address(wrapper.ciaddr, 0), wrapper.port,
                        wrapper.mac, wrapper.ciaddr,
                    )
                    wrapper.markAddressed()

    @_dhcpHandler(_PACKET_TYPE_RELEASE)
    def _handleDHCPRelease(self, wrapper):
        """
        Evaluates a RELEASE request, sent when a client terminates its "lease".

        :param :class:`_PacketWrapper` wrapper: The wrapped packet to process.
        :except _PacketSourceBanlist: The MAC appears to be generating false
                                        information to disrupt the network.
        """
        if not wrapper.sid:
            raise _PacketSourceBanlist("server-identifier was not specified")

        if wrapper.sid == self._server_address: #Released!
            if not wrapper.filterPacket(override_ip=True, override_ip_value=wrapper.ciaddr): return
            definition = wrapper.retrieveDefinition(override_ip=True, override_ip_value=wrapper.ciaddr)
            if definition and definition.ip == wrapper.ciaddr: #Known client.
                wrapper.announcePacket(ip=wrapper.ciaddr)
                wrapper.markAddressed()
            else:
                _logger.warning("{} from {} for {}, but no assignment is known".format(wrapper.getType(), wrapper.mac, wrapper.ciaddr))

    def _logDHCPAccess(self, mac):
        """
        Increments the number of times the given MAC address has accessed this
        server. If suspension is enabled and the value exceeds the policy
        threshold, the MAC is ignored as potentially belonging to a malicious
        system.

        :param :class:`libpydhcpserver.dhcp_types.mac.MAC` mac: The MAC being
                                                                evaluated.
        :return bool: True if the MAC's request should be processed.
        """
        minimal_mac = tuple(mac)
        if config.ENABLE_SUSPEND:
            with self._lock:
                actions = self._dhcp_actions.get(minimal_mac)
                if not actions:
                    self._dhcp_actions[minimal_mac] = 1
                else:
                    self._dhcp_actions[minimal_mac] += 1
                    if actions + 1 > config.SUSPEND_THRESHOLD:
                        _logger.warning("{} is issuing too many requests; ignoring for {} seconds".format(mac, config.MISBEHAVING_CLIENT_TIMEOUT))
                        self._ignored_addresses.append([minimal_mac, config.MISBEHAVING_CLIENT_TIMEOUT])
                        return False
        return True

    def _emitDHCPPacket(self, packet, address, port, mac, client_ip):
        """
        Sends the given packet to the right destination, based on its
        properties.

        :param :class:`libpydhcpserver.dhcp_types.packet.DHCPPacket` packet: The
            packet to be transmitted.
        :param :class:`libpydhcpserver.dhcp.Address` address: The address from
                                                              which the packet
                                                              was received.
        :param int port: The port from which the packet was received.
        :param :class:`libpydhcpserver.dhcp_types.mac.MAC` mac: The MAC of the
            client for which this packet is destined.
        :param :class:`libpydhcpserver.dhcp_types.ipv4.IPv4`: The IP being
            assigned to the client.
        :return int: The number of bytes emitted.
        """
        packet.setOption(54, self._server_address) #server_identifier

        (bytes, address) = self._sendDHCPPacket(packet, address, port)
        response_type = packet.getDHCPMessageTypeName()
        _logger.info("{type} sent at {mac} for {client} via {ip}:{port}[{bytes} bytes]".format(
            type=response_type[response_type.find('_') + 1:],
            mac=mac,
            client=client_ip,
            bytes=bytes,
            ip=address.ip,
            port=address.port,
        ))
        return bytes

    def addToTempBanlist(self, mac, packet_type, reason):
        """
        Marks a MAC as ignorable for a brief period of time.

        :param :class:`libpydhcpserver.dhcp_types.mac.MAC` mac: The MAC to be
                                                                ignored.
        """
        with self._lock:
            self._ignored_addresses.append([tuple(mac), config.UNAUTHORIZED_CLIENT_TIMEOUT])
        _logger.warning("{mac} was temporarily banlisted, for {time} seconds, following {packet_type}: {reason}".format(
            mac=mac,
            time=config.UNAUTHORIZED_CLIENT_TIMEOUT,
            packet_type=packet_type,
            reason=reason,
        ))

    def evaluateAbuse(self, mac):
        """
        Determines whether the MAC is, or should be, banlisted.

        :param :class:`libpydhcpserver.dhcp_types.mac.MAC` mac: The MAC to be
                                                                evaluated.
        :except _PacketSourceIgnored: The MAC is currently being ignored.
        """
        with self._lock:
            ignored = [timeout for (ignored_mac, timeout) in self._ignored_addresses if mac == ignored_mac]
        if ignored:
            raise _PacketSourceIgnored("MAC is on cooldown for another {} seconds".format(max(ignored)))

        if not self._logDHCPAccess(mac):
            raise _PacketSourceIgnored("MAC has been ignored for excessive activity")

    def getDatabase(self):
        """
        Returns the database this server is configured to use.

        :return :class:`databases.generic.Database`: The database used for
            retrieving lease definitions.
        """
        return self._database

    def getNextDHCPPacket(self):
        """
        Listens for a DHCP packet and initiates processing upon receipt.
        """
        (dhcp_received, source_address) = self._getNextDHCPPacket()
        if not dhcp_received and source_address:
            statistics.emit(statistics.Statistics(
                source_address,
                None, None,
                None, None,
                None,
                0.0, False,
                False,
            ))

    def tick(self):
        """
        Cleans up the MAC banlist and the abuse-monitoring list.
        """
        with self._lock:
            for i in reversed(range(len(self._ignored_addresses))):
                ignored_address = self._ignored_addresses[i]
                if ignored_address[1] <= 1:
                    del self._ignored_addresses[i]
                else:
                    ignored_address[1] -= 1

            if config.ENABLE_SUSPEND:
                dead_keys = []
                for (k, v) in self._dhcp_actions.items():
                    if v <= 1:
                        dead_keys.append(k)
                    else:
                        self._dhcp_actions[k] -= 1

                for k in dead_keys:
                    del self._dhcp_actions[k]


class DHCPService(threading.Thread):
    """
    A thread that handles DHCP requests indefinitely, daemonically.
    """
    _dhcp_server = None #: The handler that responds to DHCP requests.

    def __init__(self, database):
        """
        Sets up the DHCP server.

        :param :class:`databases.generic.Database` database: The database to use
                                                             for retrieving
                                                             lease definitions.
        :except Exception: A problem occurred while binding the sockets needed
                           to handle DHCP traffic.
        """
        threading.Thread.__init__(self)
        self.name = "DHCP"
        self.daemon = True

        server_address = IPv4(config.DHCP_SERVER_IP)
        _logger.info("Prepared to bind to {address}; ports: server: {server}, client: {client}, proxy: {proxy}{response_interface}".format(
            address=server_address,
            server=config.DHCP_SERVER_PORT,
            client=config.DHCP_CLIENT_PORT,
            proxy=config.PROXY_PORT,
            response_interface=config.DHCP_RESPONSE_INTERFACE and "; raw-response-interface: {response_interface}{qtags}".format(
                response_interface=config.DHCP_RESPONSE_INTERFACE,
                qtags=config.DHCP_RESPONSE_INTERFACE_QTAGS and "; raw-response-interface-qtags: {qtags!r}".format(
                    qtags=config.DHCP_RESPONSE_INTERFACE_QTAGS,
                ) or '',
            ) or '',
        ))
        self._dhcp_server = _DHCPServer(
            server_address,
            config.DHCP_SERVER_PORT,
            config.DHCP_CLIENT_PORT,
            config.PROXY_PORT,
            config.DHCP_RESPONSE_INTERFACE,
            config.DHCP_RESPONSE_INTERFACE_QTAGS,
            database
        )
        _logger.info("Configured DHCP server")

    def run(self):
        """
        Runs the DHCP server indefinitely.

        In the event of an unexpected error, e-mail will be sent and processing
        will continue with the next request.
        """
        _logger.info("DHCP engine beginning normal operation")
        while True:
            try:
                self._dhcp_server.getNextDHCPPacket()
            except select.error:
                _logger.debug("Suppressed non-fatal select() error")
            except Exception:
                _logger.critical("Unhandled exception:\n{}".format(traceback.format_exc()))

    def tick(self):
        """
        Calls the underlying tick() method.
        """
        self._dhcp_server.tick()

class _PacketRejection(Exception):
    """
    The base-class for indicating that a packet could not be processed.
    """
class _PacketSourceBanlist(_PacketRejection):
    """
    Indicates that the packet was added to a banlist, based on this event.
    """
class _PacketSourceIgnored(_PacketRejection):
    """
    Indicates that the packet's sender is currently banlisted.
    """
class _PacketSourceUnacceptable(_PacketRejection):
    """
    Indicates that the packet's sender is not permitted by policy.
    """
