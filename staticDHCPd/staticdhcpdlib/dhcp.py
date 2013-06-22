# -*- encoding: utf-8 -*-
"""
staticDHCPd module: dhcp

Purpose
=======
 Provides the DHCPd side of a staticDHCPd server.
 
Legal
=====
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
 
 (C) Neil Tallim, 2013 <flan@uguu.ca>
"""
import collections
import logging
import select
import threading
import time
import traceback

import config
import statistics

import libpydhcpserver.dhcp_network
from libpydhcpserver.dhcp_types.ipv4 import IPv4
from libpydhcpserver.dhcp_types.mac import MAC
from libpydhcpserver.dhcp_types.rfc import (
 ipToList, ipsToList,
 longToList,
 strToList,
)

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
_IP_GLOB = '0.0.0.0'
_IP_BROADCAST = '255.255.255.255'
_IP_UNSPECIFIED_FILTER = (None, '', _IP_GLOB, _IP_BROADCAST)
_IP_REJECTED = '<nil>'

_logger = logging.getLogger('dhcp')

Definition = collections.namedtuple('Definition', (
 'ip', 'hostname',
 'gateway', 'subnet_mask', 'broadcast_address',
 'domain_name', 'domain_name_servers', 'ntp_servers',
 'lease_time',
 'subnet', 'serial',
))
"""
Like the database version, only with IPv4 objects.
"""

def _extractIPOrNone(packet, parameter):
    """
    Extracts the identified packet-field-IP and returns it if it is defined,
    None otherwise.
    """
    addr = packet.getOption(parameter)
    if not addr or not any(addr):
        return None
    return IPv4(addr)
    
class _PacketWrapper(object):
    """
    Wraps a packet for the duration of a handler's operations, allowing for
    easy statistics aggregation, exception-handling, and reduction of in-line
    processing.
    """
    _server = None #:The server from which this packet was received.
    _packet_type = None #:The type of packet being wrapped.
    _discarded = True #:Whether the packet is in a discarded state.
    _start_time = None #:The time at which processing began.
    _associated_ip = None #:The client-ip associated with this request.
    _definition = None #The definition associated with this request.
    
    valid = False #:Whether the packet passed basic sanity-tests.
    source_address = None #:The (address, port) of the packet's origin.
    packet = None #:The packet being wrapped.
    mac = None #:The MAC associated with the packet.
    ip = None #:The requested IP address associated with the packet, if any.
    sid = None #:The IP address of the server associated with the request, if any.
    ciaddr = None #:The IP address of the client, if any.
    giaddr = None #:The IP address of the gateway associated with the packet, if any.
    pxe = None #:Whether the packet was received from a PXE context.
    pxe_options = None #:Any PXE options extracted from the packet.
    vendor_options = None #:Any vendor options extracted from the packet.
    
    def __init__(self, server, packet, packet_type, source_address, pxe):
        """
        Creates a new wrapper.
        
        @type server: L{_DHCPServer}
        @param server: The server associated with this packet.
        @type packet: L{libpydhcpserver.dhcp_types.packet.DHCPPacket}
        @param packet: The packet being wrapped.
        @type packet_type: basestring
        @param packet_type: The type of packet being wrapped.
        @type source_address: tuple(2)
        @param source_address: The (address:basestring, port:int) of the source.
        @type pxe: bool
        @param pxe: Whether this packet arrived via PXE.
        """
        self._start_time = time.time()
        
        self._server = server
        self._packet_type = packet_type
        self.packet = packet
        self.source_address = source_address
        self.pxe = pxe
        
        self._extractInterestingFields()
        
    def __enter__(self):
        """
        Performs validation on the packet, storing the result in 'valid'.
        
        @rtype: L{_PacketWrapper}
        @return: This object, for use with with...as constructs.
        """
        self.announcePacket(verbosity=logging.DEBUG)
        
        try:
            self._evaluateSource()
            self._server.evaluateAbuse(self.mac)
        except _PacketSourceUnacceptable, e:
            _logger.warn("Request from %(ip)s ignored: %(reason)s" % {
             'ip': self.giaddr,
             'reason': str(e),
            })
        except _PacketSourceIgnored, e:
            _logger.debug("Request from %(mac)s ignored: %(reason)s" % {
             'mac': self.mac,
             'reason': str(e),
            })
        else:
            self.valid = True
            
        return self
        
    def __exit__(self, type, value, tb):
        """
        Handles logging and notification in the event that processing terminated
        with an exception.
        
        Also ensures that statistical information is assembled and dispatched.
        """
        try:
            if isinstance(value, _PacketSourceBlacklist):
                self._server.addToTempBlacklist(self.mac, self._packet_type, str(value))
                return True
            elif isinstance(value, Exception):
                _logger.critical("Unable to handle %(type)s from  %(mac)s:\n%(error)s" % {
                 'type': self._packet_type,
                 'mac': self.mac,
                 'error': traceback.format_exc(),
                })
                return True
        finally:
            if self._discarded:
                _logger.debug("Discarded packet of type %(type)s from %(mac)s" % {
                'type': self._packet_type,
                'mac': self.mac,
                })
                
            time_taken = time.time() - self._start_time
            _logger.debug("%(type)s request from %(mac)s processed in %(seconds).4f seconds" % {
             'type': self._packet_type,
             'mac': self.mac,
             'seconds': time_taken,
            })
            
            if self._definition:
                ip = self._definition.ip
                subnet = self._definition.subnet
                serial = self._definition.serial
            else:
                subnet = serial = None
                ip = self._associated_ip
            statistics.emit(statistics.Statistics(
             self.source_address, self.mac, ip, subnet, serial, self._packet_type, time_taken, not self._discarded, self.pxe,
            ))
            
    def _extractInterestingFields(self):
        """
        Pulls commonly needed fields out of the packet, to avoid line-noise in
        the handling functions.
        """
        self.mac = self.packet.getHardwareAddress()
        self.ip = _extractIPOrNone(self.packet, "requested_ip_address")
        self.sid = _extractIPOrNone(self.packet, "server_identifier")
        self.ciaddr = _extractIPOrNone(self.packet, "ciaddr")
        self._associated_ip = self.ciaddr
        self.giaddr = _extractIPOrNone(self.packet, "giaddr")
        self.pxe_options = self.packet.extractPXEOptions()
        self.vendor_options = self.packet.extractVendorOptions()
        
    def _evaluateSource(self):
        """
        Determines whether the received packet belongs to a relayed request or
        not and decides whether it should be allowed based on policy.
        """
        if self.giaddr: #Relayed request.
            if not config.ALLOW_DHCP_RELAYS: #Ignore it.
                raise _PacketSourceUnacceptable("relay support not enabled")
            elif config.ALLOWED_DHCP_RELAYS and not self.giaddr in config.ALLOWED_DHCP_RELAYS:
                raise _PacketSourceUnacceptable("relay not authorised")
        elif not config.ALLOW_LOCAL_DHCP and not self.pxe: #Local request, but denied.
            raise _PacketSourceUnacceptable("neither link-local traffic nor PXE is enabled")
            
    def announcePacket(self, ip=None, verbosity=logging.INFO):
        """
        Logs the occurance of the wrapped packet.
        
        @type ip: basestring
        @param ip: The IP for which the quest was sent, if known.
        @type verbosity: int
        @param verbosity: A logging seerity constant.
        """
        _logger.log(verbosity, '%(type)s from %(mac)s%(ip)s%(sip)s%(pxe)s' % {
         'type': self._packet_type,
         'mac': self.mac,
         'ip': ip and (" for %(ip)s" % {'ip': ip,}) or '',
         'sip': (
          self.source_address[0] not in _IP_UNSPECIFIED_FILTER and
          " via %(address)s:%(port)i" % {'address': self.source_address[0], 'port': self.source_address[1],} or
          ''
         ),
         'pxe': self.pxe and " (PXE)" or '',
        })
        
    def getType(self):
        """
        Returns the type of packet being processed.
        
        @rtype: basestring
        @return: The type of packet being processed.
        """
        return self._packet_type
        
    def setType(self, packet_type):
        """
        Updates the type of packet being processed.
        
        @type packet_type: basestring
        @param packet_type: The type of packet being processed.
        """
        self._packet_type = packet_type
        
    def markAddressed(self):
        """
        Indicates that the packet was processed to completion.
        """
        self._discarded = False
        
    def filterPacket(self, override_ip=False, override_ip_value=None):
        """
        @type override_ip: bool
        @param override_ip: If True, override_ip_value will be used instead of
            the packet's "requested_ip_address" field.
        @type override_ip_value: sequence|None
        @param override_ip_value: The value to substitute for the default IP.
        """
        ip = self.ip
        if override_ip:
            ip = override_ip_value
            self._associated_ip = ip
            
        result = config.filterPacket(
         self.packet, self._packet_type,
         self.mac, ip, self.giaddr,
         self.pxe and self.pxe_options, self.vendor_options
        )
        if result is None:
            raise _PacketSourceBlacklist("filterPacket() returned None")
        return result
        
    def _logInvalidValue(self, name, value, subnet, serial):
        """
        Makes a note of invalid values fround in a lease definition.
        
        @type name: basestring
        @param name: The name of the field.
        @type value: any
        @param value: The offending value.
        @type subnet: basestring
        @param subnet: The subnet in which the value was found.
        @type serial: int
        @param serial: The serial in which the value was found.
        """
        _logger.error("Invalid value for %(subnet)s:%(serial)i:%(mac)s %(name)s: %(value)r" % {
         'subnet': subnet,
         'serial': serial,
         'mac': self.mac,
         'name': name,
         'value': value,
        })
        
    def _loadDHCPPacket(self, definition, inform):
        """
        Sets option fields based on values returned from the database.
        
        @type definition: L{databases.generic.Definition}
        @param definition: The value returned from the database or surrogate source.
        @type inform: bool
        @param inform: True if this is a response to an INFORM message, which
            will result in no IP being inserted into the response.
        """
        #Core parameters.
        if not inform:
            if not self.packet.setOption('yiaddr', ipToList(definition.ip)):
                self._logInvalidValue('ip', definition.ip, definition.subnet, definition.serial)
            if not self.packet.setOption('ip_address_lease_time', longToList(int(definition.lease_time))):
                self._logInvalidValue('lease_time', definition.lease_time, definition.subnet, definition.serial)
                
        #Default gateway, subnet mask, and broadcast address.
        if definition.gateway:
            if not self.packet.setOption('router', ipToList(definition.gateway)):
                _logInvalidValue('gateway', definition.gateway, definition.subnet, definition.serial)
        if definition.subnet_mask:
            if not self.packet.setOption('subnet_mask', ipToList(definition.subnet_mask)):
                _logInvalidValue('subnet_mask', definition.subnet_mask, definition.subnet, definition.serial)
        if definition.broadcast_address:
            if not self.packet.setOption('broadcast_address', ipToList(definition.broadcast_address)):
                _logInvalidValue('broadcast_address', definition.broadcast_address, definition.subnet, definition.serial)
                
        #Domain details.
        if definition.hostname:
            if not self.packet.setOption('hostname', strToList(definition.hostname)):
                _logInvalidValue('hostname', definition.hostname, definition.subnet, definition.serial)
        if definition.domain_name:
            if not self.packet.setOption('domain_name', strToList(definition.domain_name)):
                _logInvalidValue('domain_name', definition.domain_name, definition.subnet, definition.serial)
        if definition.domain_name_servers:
            if not self.packet.setOption('domain_name_servers', ipsToList(definition.domain_name_servers)):
                _logInvalidValue('domain_name_servers', definition.domain_name_servers, definition.subnet, definition.serial)
                
        #NTP servers.
        if definition.ntp_servers:
            if not self.packet.setOption('ntp_servers', ipsToList(definition.ntp_servers)):
                _logInvalidValue('ntp_servers', definition.ntp_servers, definition.subnet, definition.serial)
                
    def loadDHCPPacket(self, definition, inform=False):
        """
        Loads the packet with all normally required values, then passes it
        through custom scripting to add additional fields as needed.
        
        @type definition: L{databases.generic.Definition}
        @param definition: The definition retrieved from the database.
        @type inform: bool
        @param inform: Whether this is an INFORM scenario, which omits
            certain steps.
            
        @rtype: bool
        @return: Whether processing should continue.
        """
        self._loadDHCPPacket(definition, inform)
        process = bool(config.loadDHCPPacket(
         self.packet, self._packet_type,
         self.mac, definition.subnet, definition.serial,
         definition.ip, self.giaddr,
         self.pxe and self.pxe_options, self.vendor_options
        ))
        if not process:
            _logger.info('Ignoring %(type)s from %(mac)s per loadDHCPPacket()' % {
             'type': self._packet_type,
             'mac': self.mac,
            })
        return process
        
    def retrieveDefinition(self, override_ip=False, override_ip_value=None):
        """
        Queries the database and custom scripting to try to match the MAC to
        a lease.
        
        @type override_ip: bool
        @param override_ip: If True, override_ip_value will be used instead of
            the packet's "requested_ip_address" field.
        @type override_ip_value: sequence|None
        @param override_ip_value: The value to substitute for the default IP.
        
        @rtype: L{Definition}|None
        @return: The located Definition, or None if nothing was found.
        """
        ip = self.ip
        if override_ip:
            ip = override_ip_value
            self._associated_ip = ip
            
        definition = self._server.getDatabase().lookupMAC(self.mac) or config.handleUnknownMAC(
         self.packet, self._packet_type,
         self.mac, ip, self.giaddr,
         self.pxe and self.pxe_options, self.vendor_options
        )
        self._definition = definition and Definition(
         IPv4(definition.ip), definition.hostname,
         definition.gateway and IPv4(definition.gateway), definition.subnet_mask and IPv4(definition.subnet_mask), definition.broadcast_address and IPv4(definition.broadcast_address),
         definition.domain_name,
         definition.domain_name_servers and [IPv4(i) for i in definition.domain_name_servers.split(',')],
         definition.ntp_servers and [IPv4(i) for i in definition.ntp_servers.split(',')],
         definition.lease_time,
         definition.subnet, definition.serial,
        )
        
        return self._definition
        
def _dhcpHandler(packet_type):
    """
    A decorator to abstract away the wrapper boilerplate.
    
    @type packet_type: basestring
    @param packet_type: The type of packet initially being processed.
    """
    def decorator(f):
        def wrappedHandler(self, packet, source_address, pxe):
            with _PacketWrapper(self, packet, packet_type, source_address, pxe) as wrapper:
                if not wrapper.valid:
                    return
                f(self, wrapper)
        return wrappedHandler
    return decorator
    
class _DHCPServer(libpydhcpserver.dhcp_network.DHCPNetwork):
    """
    The handler that responds to all received requests.
    """
    _lock = None #: A lock used to ensure synchronous access to internal structures.
    _database = None #: The database to use for retrieving lease definitions.
    _dhcp_actions = None #: The MACs and the number of actions each has performed, decremented by one each tick.
    _ignored_addresses = None #: A list of all MACs currently ignored, plus the time remaining until requests will be honoured again.
    
    def __init__(self, server_address, server_port, client_port, pxe_port, database):
        """
        Constructs the handler.
        
        @type server_address: basestring
        @param server_address: The IP of the interface from which responses
            are to be sent.
        @type server_port: int
        @param server_port: The port on which DHCP requests are expected to
            arrive.
        @type client_port: int
        @param client_port: The port on which clients expect DHCP responses to
            be sent.
        @type pxe_port: int|NoneType
        @param pxe_port: The port on which to listen for PXE requests, or a
            NoneType if PXE support is disabled.
        @type database: L{databases.generic.Database}
        @param database: The database to use for retrieving lease definitions.
        
        @raise Exception: If a problem occurs while initializing the sockets
            required to process messages.
        """
        self._lock = threading.Lock()
        self._database = database
        self._dhcp_actions = {}
        self._ignored_addresses = []
        
        libpydhcpserver.dhcp_network.DHCPNetwork.__init__(
         self, server_address, server_port, client_port, pxe_port
        )
        
    @_dhcpHandler(_PACKET_TYPE_DECLINE)
    def _handleDHCPDecline(self, wrapper):
        """
        Informs the operator of a potential IP collision on the network.
        
        @type wrapper: L{_PacketWrapper}
        @param wrapper: A wrapper around the packet, exposing helpful details.
        """
        if not wrapper.ip:
            raise _PacketSourceBlacklist("conflicting IP was not specified")
            
        if not wrapper.sid:
            raise _PacketSourceBlacklist("server-identifier was not specified")
            
        if wrapper.sid == self._server_address: #Rejected!
            if not wrapper.filterPacket(): return
            
            definition = wrapper.retrieveDefinition()
            if definition and definition.ip == wrapper.ip: #Known client.
                _logger.error('%(type)s from %(mac)s for %(ip)s on (%(subnet)s, %(serial)i)' % {
                'type': wrapper.getType(),
                'ip': wrapper.ip,
                'mac': wrapper.mac,
                'subnet': definition.subnet,
                'serial': definition.serial,
                })
                wrapper.markAddressed()
            elif definition:
                _logger.warn('%(type)s from %(mac)s for %(ip)s, but its assigned IP is %(aip)s' % {
                 'type': wrapper.getType(),
                 'ip': wrapper.ip,
                 'aip': definition.ip,
                 'mac': wrapper.mac,
                })
            else:
                _logger.warn('%(type)s from %(mac)s for %(ip)s, but the MAC is unknown' % {
                 'type': wrapper.getType(),
                 'ip': wrapper.ip,
                 'mac': wrapper.mac,
                })
                
    @_dhcpHandler(_PACKET_TYPE_DISCOVER)
    def _handleDHCPDiscover(self, wrapper):
        """
        Evaluates a DISCOVER request from a client and determines whether an
        OFFER should be sent.
        
        @type wrapper: L{_PacketWrapper}
        @param wrapper: A wrapper around the packet, exposing helpful details.
        """
        if not wrapper.filterPacket(override_ip=True, override_ip_value=None): return
        wrapper.announcePacket()
        
        definition = wrapper.retrieveDefinition(override_ip=True, override_ip_value=None)
        if definition:
            rapid_commit = wrapper.packet.getOption('rapid_commit') is not None
            if rapid_commit:
                _logger.info('%(type)s from %(mac)s requested rapid-commit' % {
                 'type': wrapper.getType(),
                 'mac': wrapper.mac,
                })
                wrapper.packet.transformToDHCPAckPacket()
                wrapper.packet.forceOption('rapid_commit', [])
            else:
                wrapper.packet.transformToDHCPOfferPacket()
                
            if wrapper.loadDHCPPacket(definition):
                if rapid_commit:
                    self._emitDHCPPacket(
                     wrapper.packet, wrapper.source_address, wrapper.pxe,
                     wrapper.mac, definition.ip
                    )
                else:
                    self._emitDHCPPacket(
                     wrapper.packet, wrapper.source_address, wrapper.pxe,
                     wrapper.mac, definition.ip
                    )
                wrapper.markAddressed()
        else:
            if config.AUTHORITATIVE:
                wrapper.packet.transformToDHCPNakPacket()
                self._emitDHCPPacket(
                 wrapper.packet, wrapper.source_address, wrapper.pxe,
                 wrapper.mac, _IP_REJECTED
                )
                wrapper.markAddressed()
            else:
                raise _PacketSourceBlacklist("unknown MAC and server is not authoritative; ignoring because rejection is impossible")
                
    @_dhcpHandler(_PACKET_TYPE_INFORM)
    def _handleDHCPInform(self, wrapper):
        """
        Evaluates an INFORM request from a client and determines whether an ACK
        should be sent.
        
        @type wrapper: L{_PacketWrapper}
        @param wrapper: A wrapper around the packet, exposing helpful details.
        """
        if not wrapper.filterPacket(override_ip=True, override_ip_value=wrapper.ciaddr): return
        wrapper.announcePacket(ip=wrapper.ciaddr)
        
        if not wrapper.ciaddr:
            raise _PacketSourceBlacklist("ciaddr was not specified")
            
        definition = wrapper.retrieveDefinition(override_ip=True, override_ip_value=wrapper.ciaddr)
        if definition:
            wrapper.packet.transformToDHCPAckPacket()
            if wrapper.loadDHCPPacket(definition, inform=True):
                self._emitDHCPPacket(
                 wrapper.packet, wrapper.source_address, wrapper.pxe,
                 wrapper.mac, wrapper.ciaddr or _IP_REJECTED
                )
                wrapper.markAddressed()
        else:
            raise _PacketSourceBlacklist("unknown MAC")
            
    @_dhcpHandler(_PACKET_TYPE_LEASEQUERY)
    def _handleDHCPLeaseQuery(self, wrapper):
        """
        Simply discards the packet; LeaseQuery support was dropped in 1.7.0,
        because the implementation was wrong.
        
        @type wrapper: L{_PacketWrapper}
        @param wrapper: A wrapper around the packet, exposing helpful details.
        """
        if not wrapper.filterPacket(): return
        wrapper.announcePacket()
        
        #When reimplementing LEASEQUERY, create an alternative to the
        #'Definition' model and use that to transfer data through the wrapper
        #and handleUnknownMAC. Instead of retrieveDefinition(), it'll be
        #retrieveLeaseDefinition() and handleUnknownMAC() will need to return
        #that as a third result. Its None still means it had nothing, though.
        
    @_dhcpHandler(_PACKET_TYPE_REQUEST)
    def _handleDHCPRequest(self, wrapper):
        """
        Evaluates a REQUEST request from a client and determines whether an ACK
        should be sent.
        
        This is the most important part of the system, in which the IP a client
        claims to own is validated against the database, before it can be
        formally assigned. If the IP in question belongs to the requesting MAC,
        then an ACK is sent, along with all relevant options; if not, a NAK
        is sent to inform the client that it is not allowed to use the requested
        IP, forcing it to DISCOVER a new one.
        
        If policy forbids RENEW and REBIND operations, perhaps to prepare for a
        new configuration rollout, all such requests are NAKed immediately.
        
        @type wrapper: L{_PacketWrapper}
        @param wrapper: A wrapper around the packet, exposing helpful details.
        """
        if wrapper.sid and not wrapper.ciaddr: #SELECTING
            self._handleDHCPRequest_SELECTING(wrapper)
        elif not wrapper.sid and not wrapper.ciaddr and wrapper.ip: #INIT-REBOOT
            self._handleDHCPRequest_INIT_REBOOT(wrapper)
        elif not wrapper.sid and wrapper.ciaddr and not wrapper.ip: #RENEWING or REBINDING
            self._handleDHCPRequest_RENEW_REBIND(wrapper)
        else:
            _logger.warn('%(type)s (%(sid)s|%(ciaddr)s|%(ip)s) from %(mac)s unhandled: packet not compliant with DHCP spec' % {
             'type': wrapper.getType(),
             'sid': wrapper.sid,
             'ciaddr': wrapper.ciaddr,
             'ip': wrapper.ip,
             'mac': wrapper.mac,
            })
            
    def _handleDHCPRequest_SELECTING(self, wrapper):
        wrapper.setType(_PACKET_TYPE_REQUEST_SELECTING)
        if wrapper.sid == self._server_address: #Chosen!
            if not wrapper.filterPacket(): return
            wrapper.announcePacket(ip=wrapper.ip)
            
            definition = wrapper.retrieveDefinition()
            if definition and (not wrapper.ip or definition.ip == wrapper.ip):
                wrapper.packet.transformToDHCPAckPacket()
                if wrapper.loadDHCPPacket(definition):
                    self._emitDHCPPacket(
                     wrapper.packet, wrapper.source_address, wrapper.pxe,
                     wrapper.mac, wrapper.ip
                    )
                    wrapper.markAddressed()
            else:
                wrapper.packet.transformToDHCPNakPacket()
                self._emitDHCPPacket(
                 wrapper.packet, wrapper.source_address, wrapper.pxe,
                 wrapper.mac, _IP_REJECTED
                )
                wrapper.markAddressed()
                
    def _handleDHCPRequest_INIT_REBOOT(self, wrapper):
        wrapper.setType(_PACKET_TYPE_REQUEST_INIT_REBOOT)
        if not wrapper.filterPacket(): return
        wrapper.announcePacket(ip=wrapper.ip)
        
        definition = wrapper.retrieveDefinition()
        if definition and definition.ip == wrapper.ip:
            wrapper.packet.transformToDHCPAckPacket()
            if wrapper.loadDHCPPacket(definition):
                self._emitDHCPPacket(
                 wrapper.packet, wrapper.source_address, wrapper.pxe,
                 wrapper.mac, wrapper.ip
                )
                wrapper.markAddressed()
        else:
            wrapper.packet.transformToDHCPNakPacket()
            self._emitDHCPPacket(
             wrapper.packet, wrapper.source_address, wrapper.pxe,
             wrapper.mac, wrapper.ip
            )
            wrapper.markAddressed()
            
    def _handleDHCPRequest_RENEW_REBIND(self, wrapper):
        renew = wrapper.source_address[0] not in _IP_UNSPECIFIED_FILTER
        wrapper.setType(renew and _PACKET_TYPE_REQUEST_RENEW or _PACKET_TYPE_REQUEST_REBIND)
        if not wrapper.filterPacket(): return
        wrapper.announcePacket(ip=wrapper.ip)
        
        if config.NAK_RENEWALS and not wrapper.pxe and (renew or config.AUTHORITATIVE):
            wrapper.packet.transformToDHCPNakPacket()
            self._emitDHCPPacket(
             wrapper.packet, wrapper.source_address, wrapper.pxe,
             wrapper.mac, _IP_REJECTED
            )
            wrapper.markAddressed()
        else:
            definition = wrapper.retrieveDefinition()
            if definition and definition.ip == wrapper.ciaddr:
                wrapper.packet.transformToDHCPAckPacket()
                wrapper.packet.setOption('yiaddr', wrapper.ciaddr)
                if wrapper.loadDHCPPacket(definition):
                    self._emitDHCPPacket(
                     wrapper.packet, (wrapper.ciaddr, 0), wrapper.pxe,
                     wrapper.mac, wrapper.ciaddr
                    )
                    wrapper.markAddressed()
            else:
                if renew:
                    wrapper.packet.transformToDHCPNakPacket()
                    self._emitDHCPPacket(
                     wrapper.packet, (wrapper.ciaddr, 0), wrapper.pxe,
                     wrapper.mac, wrapper.ciaddr
                    )
                    wrapper.markAddressed()
                    
    @_dhcpHandler(_PACKET_TYPE_RELEASE)
    def _handleDHCPRelease(self, wrapper):
        """
        Handles a client that has terminated its "lease".
        
        @type wrapper: L{_PacketWrapper}
        @param wrapper: A wrapper around the packet, exposing helpful details.
        """
        if not wrapper.sid:
            raise _PacketSourceBlacklist("server-identifier was not specified")
            
        if wrapper.sid == self._server_address: #Released!
            if not wrapper.filterPacket(override_ip=True, override_ip_value=wrapper.ciaddr): return
            definition = wrapper.retrieveDefinition(override_ip=True, override_ip_value=wrapper.ciaddr)
            if definition and definition.ip == wrapper.ciaddr: #Known client.
                wrapper.announcePacket(ip=wrapper.ciaddr)
                wrapper.markAddressed()
            else:
                _logger.warn('%(type)s from %(mac)s for %(ip)s, but no assignment is known' % {
                 'type': wrapper.getType(),
                 'ip': wrapper.ciaddr,
                 'mac': wrapper.mac,
                })
                
    def _logDHCPAccess(self, mac):
        """
        Increments the number of times the given MAC address has accessed this
        server. If the value exceeds the policy threshold, the MAC is ignored as
        potentially belonging to a malicious user.
        
        @type mac: basestring
        @param mac: The MAC being evaluated.
        
        @rtype: bool
        @return: True if the MAC's request should be processed.
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
                        _logger.warn('%(mac)s is issuing too many requests; ignoring for %(time)i seconds' % {
                         'mac': mac,
                         'time': config.MISBEHAVING_CLIENT_TIMEOUT,
                        })
                        self._ignored_addresses.append([minimal_mac, config.MISBEHAVING_CLIENT_TIMEOUT])
                        return False
        return True
        
    def _emitDHCPPacket(self, packet, address, pxe, mac, client_ip):
        """
        Sends the given packet to the right destination based on its properties.
        
        If the request originated from a host that knows its own IP, the packet
        is transmitted via unicast; in the event of a relayed request, it is sent
        to the 'server port', rather than the 'client port', per RFC 2131.
        
        If it was picked up as a broadcast packet, it is sent to the local subnet
        via the same mechanism, but to the 'client port'.
        
        @type packet: L{libpydhcpserver.dhcp_types.packet.DHCPPacket}
        @param packet: The packet to be transmitted.
        @type address: tuple
        @param address: The address from which the packet was received:
            (host, port)
        @type pxe: bool
        @param pxe: True if the packet was received via the PXE port.
        @type mac: basestring
        @param mac: The MAC of the client for which this packet is destined.
        @type client_ip: basestring
        @param client_ip: The IP being assigned to the client.
            
        @rtype: int
        @return: The number of bytes transmitted.
        """
        ip = port = None
        if address[0] in _IP_UNSPECIFIED_FILTER: #Broadcast
            ip = _IP_BROADCAST
            port = self._client_port
        else: #Unicast
            giaddr = _extractIPOrNone(packet, 'giaddr')
            if giaddr: #Relayed request.
                port = self._server_port
            else: #Request directly from client, routed or otherwise.
                ip = address[0]
                if pxe:
                    ip = _extractIPOrNone(packet, 'ciaddr') or ip
                    port = address[1] or self._client_port #BSD doesn't seem to preserve port information
                else:
                    port = self._client_port
                    
        packet.setOption('server_identifier', ipToList(self._server_address))
        bytes = self._sendDHCPPacket(packet, ip, port, pxe)
        response_type = packet.getDHCPMessageTypeName()
        _logger.info('%(type)s sent to %(mac)s for %(client)s via %(ip)s:%(port)i %(pxe)s[%(bytes)i bytes]' % {
         'type': response_type[response_type.find('_') + 1:],
         'mac': mac,
         'client': client_ip,
         'bytes': bytes,
         'ip': ip,
         'port': port,
         'pxe': pxe and '(PXE) ' or '',
        })
        return bytes
        
    def addToTempBlacklist(self, mac, packet_type, reason):
        """
        Marks a MAC as ignorable for a nominal amount of time.
        
        @type mac: basestring
        @param mac: The MAC to be ignored.
        """
        with self._lock:
            self._ignored_addresses.append([tuple(mac), config.UNAUTHORIZED_CLIENT_TIMEOUT])
        _logger.warn('%(mac)s was temporarily blacklisted, for %(time)i seconds, following %(packet_type)s: %(reason)s' % {
         'mac': mac,
         'time': config.UNAUTHORIZED_CLIENT_TIMEOUT,
         'packet_type': packet_type,
         'reason': reason,
        })
        
    def evaluateAbuse(self, mac):
        """
        Determines whether the MAC is, or should be, blacklisted.
        
        @type mac: basestring
        @param mac: The MAC to be evaluated.
        
        @raise _PacketSourceIgnored: The MAC is currently being ignored.
        """
        with self._lock:
            ignored = [timeout for (ignored_mac, timeout) in self._ignored_addresses if mac == ignored_mac]
        if ignored:
            raise _PacketSourceIgnored("MAC is on cooldown for another %(count)i seconds" % {'count': max(ignored)})
            
        if not self._logDHCPAccess(mac):
            raise _PacketSourceIgnored("MAC has been ignored for excessive activity")
            
    def getDatabase(self):
        """
        Returns the database this server is configured to use.
        
        @rtype: L{databases.generic.Database}
        @return: The database to use for retrieving lease definitions.
        """
        return self._database
        
    def getNextDHCPPacket(self):
        """
        Listens for a DHCP packet and initiates processing upon receipt.
        """
        (dhcp_received, source_address) = self._getNextDHCPPacket()
        if not dhcp_received and source_address:
            statistics.emit(statistics.Statistics(
             source_address, None, None, None, None, None, 0.0, False, False
            ))
            
    def tick(self):
        """
        Cleans up the MAC blacklist and the abuse-monitoring list.
        """
        with self._lock:
            for i in reversed(xrange(len(self._ignored_addresses))):
                ignored_address = self._ignored_addresses[i]
                if ignored_address[1] <= 1:
                    del self._ignored_addresses[i]
                else:
                    ignored_address[1] -= 1
                    
            if config.ENABLE_SUSPEND:
                dead_keys = []
                for (k, v) in self._dhcp_actions.iteritems():
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
        
        @type database: L{databases.generic.Database}
        @param database: The database to use for retrieving lease definitions.
        
        @raise Exception: If a problem occurs while binding the sockets needed
            to handle DHCP traffic.
        """
        threading.Thread.__init__(self)
        self.name = "DHCP"
        self.daemon = True
        
        server_address = '.'.join([str(int(o)) for o in config.DHCP_SERVER_IP.split('.')])
        _logger.info("Prepared to bind to %(address)s; ports: server: %(server)s, client: %(client)s, pxe: %(pxe)s" % {
         'address': server_address,
         'server': config.DHCP_SERVER_PORT,
         'client': config.DHCP_CLIENT_PORT,
         'pxe': config.PXE_PORT,
        })
        self._dhcp_server = _DHCPServer(
         server_address,
         config.DHCP_SERVER_PORT,
         config.DHCP_CLIENT_PORT,
         config.PXE_PORT,
         database
        )
        _logger.info("Configured DHCP server")
        
    def run(self):
        """
        Runs the DHCP server indefinitely.
        
        In the event of an unexpected error, e-mail will be sent and processing
        will continue with the next request.
        """
        _logger.info('DHCP engine beginning normal operation')
        while True:
            try:
                self._dhcp_server.getNextDHCPPacket()
            except select.error:
                _logger.debug('Suppressed non-fatal select() error')
            except Exception:
                _logger.critical("Unhandled exception:\n" + traceback.format_exc())
                
    def tick(self):
        """
        Calls the underying tick() method.
        """
        self._dhcp_server.tick()
    
class _PacketRejection(Exception):
    """
    The base-class for indicating that a packet could not be processed.
    """
    
class _PacketSourceBlacklist(_PacketRejection):
    """
    Indicates that the packet was added to a blacklist, based on this event.
    """
    
class _PacketSourceIgnored(_PacketRejection):
    """
    Indicates that the packet's sender is currently blacklisted.
    """
    
class _PacketSourceUnacceptable(_PacketRejection):
    """
    Indicates that the packet's sender is not permitted by policy.
    """
    
