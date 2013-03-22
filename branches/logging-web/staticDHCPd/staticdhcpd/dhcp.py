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
import system

import libpydhcpserver.dhcp_network
from libpydhcpserver.type_rfc import (
 ipToList, ipsToList,
 intToList, intsToList,
 longToList, longsToList,
 strToList, strToPaddedList,
)

_Definition = collections.namedtuple('Definition', (
 'ip', 'hostname',
 'gateway', 'subnet_mask', 'broadcast_address',
 'domain_name', 'domain_name_servers', 'ntp_servers',
 'lease_time',
 'subnet', 'serial',
))

_logger = logging.getLogger('dhcp')

def _extractIPOrNone(packet, parameter):
    """
    Extracts the identified IP and returns it if it is defined, None otherwise.
    
    @type packet: L{libpydhcpserver.dhcp_packet.DHCPPacket}
    @param packet: The packet to be evaluated.
    @type parameter: basestring
    @param parameter: The parameter to be extracted.
        
    @rtype: list|None
    @return: The requested IP.
    """
    addr = packet.getOption(parameter)
    if not addr or not any(addr):
        return None
    return addr
    
def _toDottedQuadOrNone(ip):
    """
    Converts a sequence of integers into a human-readable IP.
    
    @type ip: list|tuple|None
    @param ip: The IP to be converted.
    
    @rtype: string|None
    @return: The converted value.
    """
    return ip and '.'.join(map(str, ip))
    
    
class _PacketWrapper(object):
    """
    Wraps a packet for the duration of a handler's operations, allowing for
    easy statistics aggregation, exception-handling, and reduction of in-line
    processing.
    """
    _server = None #:The DHCP server from which this packet was received.
    _packet = None #:The packet being wrapped.
    _packet_type = None #:The type of packet being wrapped.
    _discarded = True #:Whether the packet is in a discarded state.
    _pxe = None #:Whether the packet was received from a PXE context.
    _start_time = None #:The time at which processing began.
    
    valid = False #:Whether the packet passed basic sanity-tests.
    mac = None #:The MAC associated with the packet.
    ip = None #:The requested IP address associated with the packet, if any.
    sid = None #:The IP address of the server associated with the request, if any.
    ciaddr = None #:The IP address of the client, if any.
    giaddr = None #:The IP address of the gateway associated with the packet, if any.
    pxe_options = None #:Any PXE options extracted from the packet.
    vendor_options = None #:Any vendor options extracted from the packet.
    
    def __init__(self, server, packet, packet_type, pxe):
        """
        Creates a new wrapper.
        
        @type server: L{_DHCPServer}
        @param server: The server associated with this packet.
        @type packet: L{libpydhcpserver.dhcp_packet.DHCPPacket}
        @param packet: The packet being wrapped.
        @type packet_type: basestring
        @param packet_type: The type of packet being wrapped.
        @type pxe: bool
        @param pxe: Whether this packet arrived via PXE.
        """
        self._start_time = time.time()
        
        self._server = server
        self._packet = packet
        self._packet_type = packet_type
        self._pxe = pxe
        
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
             'ip': _toDottedQuadOrNone(self.giaddr),
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
                _logger.warn('%(mac)s was temporarily blacklisted, for %(time)i seconds: %(reason)s' % {
                 'mac': self.mac,
                 'time': config.UNAUTHORIZED_CLIENT_TIMEOUT,
                 'reason': str(value),
                })
                self._server.addToTempBlacklist(self.mac)
                return True
            elif isinstance(value, Exception):
                _logger.critical("Unable to handle %(type)s from  %(mac)s:\n%(error)s" % {
                 'type': self._packet_type,
                 'mac': self.mac,
                 'error': traceback.format_exc(),
                })
                return True
        finally:
            #Add receipt-notification to stats
            
            if self._discarded:
                _logger.debug("Discarded packet of type %(type)s from %(mac)s" % {
                'type': self._packet_type,
                'mac': self.mac,
                })
                #Add to stats
                
            time_taken = time.time() - self._start_time
            _logger.debug("%(type)s request from %(mac)s processed in %(seconds).4f seconds" % {
             'type': self._packet_type,
             'mac': self.mac,
             'seconds': time_taken,
            })
            system.STATISTICS_DHCP.trackProcessingTime(time_taken)
            
    def _extractInterestingFields(self):
        """
        Pulls commonly needed fields out of the packet, to avoid line-noise in
        the handling functions.
        """
        self.mac = self._packet.getHardwareAddress()
        self.ip = _extractIPOrNone(self._packet, "requested_ip_address")
        self.sid = _extractIPOrNone(self._packet, "server_identifier")
        self.ciaddr = _extractIPOrNone(self._packet, "ciaddr")
        self.giaddr = _extractIPOrNone(self._packet, "giaddr")
        self.pxe_options = self._packet.extractPXEOptions()
        self.vendor_options = self._packet.extractVendorOptions()
        
    def _evaluateSource(self):
        """
        Determines whether the received packet belongs to a relayed request or
        not and decides whether it should be allowed based on policy.
        
        @type packet: L{libpydhcpserver.dhcp_packet.DHCPPacket}
        @param packet: The packet to be evaluated.
        @type pxe: bool
        @param pxe: Whether the request is PXE
        """
        if self.giaddr: #Relayed request.
            if not config.ALLOW_DHCP_RELAYS: #Ignore it.
                raise _PacketSourceUnacceptable("relay support not enabled")
            elif config.ALLOWED_DHCP_RELAYS and not '.'.join(map(str, giaddr)) in config.ALLOWED_DHCP_RELAYS:
                raise _PacketSourceUnacceptable("relay not authorised")
        elif not config.ALLOW_LOCAL_DHCP and not pxe: #Local request, but denied.
            raise _PacketSourceUnacceptable("neither link-local traffic nor PXE is enabled")
            
    def announcePacket(self, verbosity=logging.INFO):
        """
        Logs the occurance of the wrapped packet.
        
        @type verbosity: int
        @param verbosity: A logging seerity constant.
        """
        _logger.log(verbosity, '%(type)s from %(mac)s' % {
         'type': self._packet_type,
         'mac': self.mac,
        })
        
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
        Sets DHCP option fields based on values returned from the database.
        
        @type definition: _Definition
        @param definition: The value returned from the database or surrogate source.
        @type inform: bool
        @param inform: True if this is a response to a DHCPINFORM message, which
            will result in no IP being inserted into the response.
        """
        #Core parameters.
        if not inform:
            if not self._packet.setOption('yiaddr', ipToList(definition.ip)):
                self._logInvalidValue('ip', definition.ip, definition.subnet, definition.serial)
            if not self._packet.setOption('ip_address_lease_time', longToList(int(definition.lease_time))):
                self._logInvalidValue('lease_time', definition.lease_time, definition.subnet, definition.serial)
                
        #Default gateway, subnet mask, and broadcast address.
        if definition.gateway:
            if not self._packet.setOption('router', ipToList(definition.gateway)):
                _logInvalidValue('gateway', definition.gateway, definition.subnet, definition.serial)
        if definition.subnet_mask:
            if not self._packet.setOption('subnet_mask', ipToList(definition.subnet_mask)):
                _logInvalidValue('subnet_mask', definition.subnet_mask, definition.subnet, definition.serial)
        if definition.broadcast_address:
            if not self._packet.setOption('broadcast_address', ipToList(definition.broadcast_address)):
                _logInvalidValue('broadcast_address', definition.broadcast_address, definition.subnet, definition.serial)
                
        #Domain details.
        if definition.hostname:
            if not self._packet.setOption('hostname', strToList(definition.hostname)):
                _logInvalidValue('hostname', definition.hostname, definition.subnet, definition.serial)
        if definition.domain_name:
            if not self._packet.setOption('domain_name', strToList(definition.domain_name)):
                _logInvalidValue('domain_name', definition.domain_name, definition.subnet, definition.serial)
        if definition.domain_name_servers:
            if not self._packet.setOption('domain_name_servers', ipsToList(definition.domain_name_servers)):
                _logInvalidValue('domain_name_servers', definition.domain_name_servers, definition.subnet, definition.serial)
                
        #NTP servers.
        if definition.ntp_servers:
            if not self._packet.setOption('ntp_servers', ipsToList(definition.ntp_servers)):
                _logInvalidValue('ntp_servers', definition.ntp_servers, definition.subnet, definition.serial)
                
    def loadDHCPPacket(self, definition, inform=False):
        """
        Loads the packet with all normally required values, then passes it
        through custom scripting to add additional fields as needed.
        
        @type definition: Definition
        @param definition: The definition retrieved from the database.
        @type inform: bool
        @param inform: Whether this is a DHCP INFORM scenario, which omits
            certain steps.
            
        @rtype: bool
        @return: Whether processing should continue.
        """
        self._loadDHCPPacket(definition, inform)
        process = bool(config.loadDHCPPacket(
         self._packet, self._packet_type,
         self.mac, tuple(ipToList(definition.ip)), self.giaddr and tuple(self.giaddr),
         definition.subnet, definition.serial,
         self._pxe and self.pxe_options, self.vendor_options
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
        
        @rtype: Definition|None
        @return: The located Definition, or None if nothing was found.
        """
        ip = self.ip
        if override_ip:
            ip = override_ip_value
            
        result = system.DATABASE.lookupMAC(self.mac) or config.handleUnknownMAC(
         self._packet, self._packet_type,
         self.mac, ip and tuple(ip), self.giaddr and tuple(self.giaddr),
         self._pxe and self.pxe_options, self.vendor_options
        )
        if result:
            return _Definition(*result)
        return None
        
class _DHCPServer(libpydhcpserver.dhcp_network.DHCPNetwork):
    """
    The handler that responds to all received DHCP requests.
    """
    _lock = None #: A lock used to ensure synchronous access to internal structures.
    _dhcp_actions = None #: The MACs and the number of DHCP actions each has performed, decremented by one each tick.
    _ignored_addresses = None #: A list of all MACs currently ignored, plus the time remaining until requests will be honoured again.
    _packets_discarded = 0 #: The number of packets discarded since the last polling interval.
    _packets_processed = 0 #: The number of packets processed since the last polling interval.
    _time_taken = 0.0 #: The amount of time taken since the last polling interval.
    
    def __init__(self, server_address, server_port, client_port, pxe_port):
        """
        Constructs the DHCP handler.
        
        @type server_address: basestring
        @param server_address: The IP of the interface from which DHCP responses
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
        
        @raise Exception: If a problem occurs while initializing the sockets
            required to process DHCP messages.
        """
        self._lock = threading.Lock()
        self._dhcp_actions = {}
        self._ignored_addresses = []
        
        libpydhcpserver.dhcp_network.DHCPNetwork.__init__(
            self, server_address, server_port, client_port, pxe_port
        )
        
    def _handleDHCPDecline(self, packet, source_address, pxe):
        """
        Informs the operator of a potential IP collision on the network.
        
        @type packet: L{libpydhcpserver.dhcp_packet.DHCPPacket}
        @param packet: The DHCPDISCOVER to be evaluated.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        with _PacketWrapper(self, packet, 'DECLINE', pxe) as wrapper:
            if not wrapper.valid: return
            
            if not wrapper.ip:
                raise _PacketSourceBlacklist("DECLINE sent without indicating the conflicting IP")
                
            if not wrapper.sid:
                raise _PacketSourceBlacklist("DECLINE sent without a server-identifier")
                
            if _toDottedQuadOrNone(wrapper.sid) == self._server_address: #Rejected!
                definition = wrapper.retrieveDefinition()
                ip = _toDottedQuadOrNone(wrapper.ip)
                if definition and definition.ip == ip: #Known client.
                    _logger.error('DECLINE from %(mac)s for %(ip)s on (%(subnet)s, %(serial)i)' % {
                     'ip': ip,
                     'mac': wrapper.mac,
                     'subnet': definition.subnet,
                     'serial': definition.serial,
                    })
                    wrapper.markAddressed()
                else:
                    _logger.warn('%(mac)s sent DECLINE for %(ip)s to this server, but the MAC is unknown' % {
                     'ip': ip,
                     'mac': wrapper.mac,
                    })
                    
    def _handleDHCPDiscover(self, packet, source_address, pxe):
        """
        Evaluates a DHCPDISCOVER request from a client and determines whether a
        DHCPOFFER should be sent.
        
        @type packet: L{libpydhcpserver.dhcp_packet.DHCPPacket}
        @param packet: The DHCPDISCOVER to be evaluated.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        with _PacketWrapper(self, packet, 'DISCOVER', pxe) as wrapper:
            if not wrapper.valid: return
            wrapper.announcePacket()
            
            definition = wrapper.retrieveDefinition(override_ip=True, override_ip_value=None)
            if definition:
                rapid_commit = packet.getOption('rapid_commit') is not None
                if rapid_commit:
                    packet.transformToDHCPAckPacket()
                    packet.forceOption('rapid_commit', [])
                else:
                    packet.transformToDHCPOfferPacket()
                    
                if wrapper.loadDHCPPacket(definition):
                    if rapid_commit:
                        self._sendDHCPPacket(packet, source_address, 'ACK-rapid', wrapper.mac, definition.ip, pxe)
                    else:
                        self._sendDHCPPacket(packet, source_address, 'OFFER', wrapper.mac, definition.ip, pxe)
                    wrapper.markAddressed()
            else:
                if config.AUTHORITATIVE:
                    packet.transformToDHCPNackPacket()
                    self._sendDHCPPacket(packet, source_address, 'NAK', wrapper.mac, '?.?.?.?', pxe)
                    wrapper.markAddressed()
                else:
                    raise _PacketSourceBlacklist("unknown MAC and server is not authoritative, so a NAK cannot be sent")
                    
    def _handleDHCPLeaseQuery(self, packet, source_address, pxe):
        """
        Simply discards the packet; LeaseQuery support was dropped in 1.6.3,
        because the implementation was wrong.
        
        @type packet: L{libpydhcpserver.dhcp_packet.DHCPPacket}
        @param packet: The DHCPREQUEST to be evaluated.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        with _PacketWrapper(self, packet, 'LEASEQUERY', pxe) as wrapper:
            if not wrapper.valid: return
            wrapper.announcePacket()
            
    def _handleDHCPRequest(self, packet, source_address, pxe):
        """
        Evaluates a DHCPREQUEST request from a client and determines whether a
        DHCPACK should be sent.
        
        This is the most important part of the system, in which the IP a client
        claims to own is validated against the database, before it can be
        formally assigned. If the IP in question belongs to the requesting MAC,
        then an ACK is sent, along with all relevant options; if not, a DHCPNAK
        is sent to inform the client that it is not allowed to use the requested
        IP, forcing it to DISCOVER a new one.
        
        If policy forbids RENEW and REBIND operations, perhaps to prepare for a
        new configuration rollout, all such requests are NAKed immediately.
        
        @type packet: L{libpydhcpserver.dhcp_packet.DHCPPacket}
        @param packet: The DHCPREQUEST to be evaluated.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        with _PacketWrapper(self, packet, 'REQUEST', pxe) as wrapper:
            if not wrapper.valid: return
            
            s_ip = _toDottedQuadOrNone(wrapper.ip)
            s_sid = _toDottedQuadOrNone(wrapper.sid)
            s_ciaddr = _toDottedQuadOrNone(wrapper.ciaddr)
            
            if wrapper.sid and not wrapper.ciaddr: #SELECTING
                wrapper.setType('REQUEST:SELECTING')
                if s_sid == self._server_address: #Chosen!
                    wrapper.announcePacket()
                    
                    definition = wrapper.retrieveDefinition()
                    if definition and (not wrapper.ip or definition.ip == s_ip):
                        packet.transformToDHCPAckPacket()
                        if wrapper.loadDHCPPacket(definition):
                            self._sendDHCPPacket(packet, source_address, 'ACK', wrapper.mac, s_ip, pxe)
                            wrapper.markAddressed()
                    else:
                        packet.transformToDHCPNackPacket()
                        self._sendDHCPPacket(packet, source_address, 'NAK', wrapper.mac, 'NO-MATCH', pxe)
                        wrapper.markAddressed()
            elif not wrapper.sid and not wrapper.ciaddr and wrapper.ip: #INIT-REBOOT
                wrapper.setType('REQUEST:INIT-REBOOT')
                wrapper.announcePacket()
                
                definition = wrapper.retrieveDefinition()
                if definition and definition.ip == s_ip:
                    packet.transformToDHCPAckPacket()
                    if wrapper.loadDHCPPacket(definition):
                        self._sendDHCPPacket(packet, source_address, 'ACK', wrapper.mac, s_ip, pxe)
                        wrapper.markAddressed()
                else:
                    packet.transformToDHCPNackPacket()
                    self._sendDHCPPacket(packet, source_address, 'NAK', wrapper.mac, s_ip, pxe)
                    wrapper.markAddressed()
            elif not wrapper.sid and wrapper.ciaddr and not wrapper.ip: #RENEWING or REBINDING
                renew = source_address[0] not in ('255.255.255.255', '0.0.0.0', '')
                wrapper.setType('REQUEST:' + (renew and 'RENEW' or 'REBIND'))
                wrapper.announcePacket()
                
                if config.NAK_RENEWALS and not pxe:
                    packet.transformToDHCPNackPacket()
                    self._sendDHCPPacket(packet, source_address, 'NAK', wrapper.mac, 'NAK_RENEWALS', pxe)
                    wrapper.markAddressed()
                else:
                    definition = wrapper.retrieveDefinition()
                    if definition and definition.ip == s_ciaddr:
                        packet.transformToDHCPAckPacket()
                        packet.setOption('yiaddr', wrapper.ciaddr)
                        if wrapper.loadDHCPPacket(definition):
                            self._sendDHCPPacket(packet, (s_ciaddr, 0), 'ACK', wrapper.mac, s_ciaddr, pxe)
                            wrapper.markAddressed()
                    else:
                        if renew:
                            packet.transformToDHCPNackPacket()
                            self._sendDHCPPacket(packet, (s_ciaddr, 0), 'NAK', wrapper.mac, s_ciaddr, pxe)
                            wrapper.markAddressed()
            else:
                _logger.warn('REQUEST:UNKNOWN (%(sid)s|%(ciaddr)s|%(ip)s) from %(mac)s' % {
                 'sid': s_sid,
                 'ciaddr': s_ciaddr,
                 'ip': s_ip,
                 'mac': wrapper.mac,
                })
                
    def _handleDHCPInform(self, packet, source_address, pxe):
        """
        Evaluates a DHCPINFORM request from a client and determines whether a
        DHCPACK should be sent.
        
        @type packet: L{libpydhcpserver.dhcp_packet.DHCPPacket}
        @param packet: The DHCPREQUEST to be evaluated.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        with _PacketWrapper(self, packet, 'INFORM', pxe) as wrapper:
            if not wrapper.valid: return
            wrapper.announcePacket()
            
            if not wrapper.ciaddr:
                raise _PacketSourceBlacklist("malformed packet did not include ciaddr")
                
            definition = wrapper.retrieveDefinition(override_ip, override_ip_value=wrapper.ciaddr)
            if definition:
                packet.transformToDHCPAckPacket()
                if wrapper.loadDHCPPacket(definition, inform=True):
                    self._sendDHCPPacket(
                     packet,
                     source_address, 'ACK', wrapper.mac, _toDottedQuadOrNone(wrapper.ciaddr) or '0.0.0.0',
                     pxe
                    )
                    wrapper.markAddressed()
            else:
                raise _PacketSourceBlacklist("unknown MAC")
                
    def _handleDHCPRelease(self, packet, source_address, pxe):
        """
        Informs the DHCP operator that a client has terminated its "lease".
        
        @type packet: L{libpydhcpserver.dhcp_packet.DHCPPacket}
        @param packet: The DHCPDISCOVER to be evaluated.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        with _PacketWrapper(self, packet, 'RELEASE', pxe) as wrapper:
            if not wrapper.valid: return
            
            if not wrapper.sid:
                raise _PacketSourceBlacklist("RELEASE sent without server-identifier")
                
            if _toDottedQuadOrNone(wrapper.sid) == self._server_address: #Released!
                definition = wrapper.retrieveDefinition(override_ip=True, override_ip_value=wrapper.ciaddr)
                ip = _toDottedQuadOrNone(wrapper.ciaddr)
                if definition and definition.ip == ip: #Known client.
                    _logger.info('RELEASE from %(mac)s for %(ip)s' % {
                     'ip': ip,
                     'mac': wrapper.mac,
                    })
                    wrapper.markAddressed()
                else:
                    _logger.warn('Misconfigured client %(mac)s sent RELEASE for %(ip)s, for which it has no assignment' % {
                        'ip': ip,
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
        if config.ENABLE_SUSPEND:
            with self._lock:
                actions = self._dhcp_actions.get(mac)
                if not actions:
                    self._dhcp_actions[mac] = 1
                else:
                    self._dhcp_actions[mac] += 1
                    if actions + 1 > config.SUSPEND_THRESHOLD:
                        _logger.warn('%(mac)s is issuing too many requests; ignoring for %(time)i seconds' % {
                         'mac': mac,
                         'time': config.MISBEHAVING_CLIENT_TIMEOUT,
                        })
                        self._ignored_addresses.append([mac, config.MISBEHAVING_CLIENT_TIMEOUT])
                        return False
        return True
        
    def _sendDHCPPacket(self, packet, address, response_type, mac, client_ip, pxe):
        """
        Sends the given packet to the right destination based on its properties.
        
        If the request originated from a host that knows its own IP, the packet
        is transmitted via unicast; in the event of a relayed request, it is sent
        to the 'server port', rather than the 'client port', per RFC 2131.
        
        If it was picked up as a broadcast packet, it is sent to the local subnet
        via the same mechanism, but to the 'client port'.
        
        @type packet: L{libpydhcpserver.dhcp_packet.DHCPPacket}
        @param packet: The packet to be transmitted.
        @type address: tuple
        @param address: The address from which the packet was received:
            (host, port)
        @type response_type: basestring
        @param response_type: The DHCP subtype of this response: 'OFFER', 'ACK',
            'NAK'
        @type mac: basestring
        @param mac: The MAC of the client for which this packet is destined.
        @type client_ip: basestring
        @param client_ip: The IP being assigned to the client.
        @type pxe: bool
        @param pxe: True if the packet was received via the PXE port
        
        @rtype: int
        @return: The number of bytes transmitted.
        """
        ip = port = None
        if address[0] not in ('255.255.255.255', '0.0.0.0', ''): #Unicast.
            giaddr = _extractIPOrNone(packet, "giaddr")
            if giaddr: #Relayed request.
                ip = _toDottedQuadOrNone(giaddr)
                port = self._server_port
            else: #Request directly from client, routed or otherwise.
                ip = address[0]
                if pxe:
                    port = address[1] or self._client_port #BSD doesn't seem to preserve port information
                else:
                    port = self._client_port
        else: #Broadcast.
            ip = '255.255.255.255'
            port = self._client_port
            
        packet.setOption('server_identifier', ipToList(self._server_address))
        bytes = self._sendDHCPPacketTo(packet, ip, port, pxe)
        _logger.info('%(type)s sent to %(mac)s for %(client)s via %(ip)s:%(port)i %(pxe)s[%(bytes)i bytes]' % {
         'type': response_type,
         'mac': mac,
         'client': client_ip,
         'bytes': bytes,
         'ip': ip,
         'port': port,
         'pxe': pxe and '(PXE) ' or '',
        })
        return bytes
        
    def addToTempBlacklist(self, mac):
        """
        Marks a MAC as ignorable for a nominal amount of time.
        
        @type mac: basestring
        @param mac: The MAC to be ignored.
        """
        with self._lock:
            self._ignored_addresses.append([mac, config.UNAUTHORIZED_CLIENT_TIMEOUT])
            
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
            
    def getNextDHCPPacket(self):
        """
        Listens for a DHCP packet and initiates processing upon receipt.
        """
        if not self._getNextDHCPPacket():
            system.STATISTICS_DHCP.trackOtherPacket()
            
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
    
    def __init__(self):
        """
        Sets up the DHCP server.
        
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
         config.PXE_PORT
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
    
class _PacketSourceIgnored(_PacketRejection):
    """
    Indicates that the packet's sender is currently blacklisted.
    """
    
class _PacketSourceUnacceptable(_PacketRejection):
    """
    Indicates that the packet's sender is not permitted by policy.
    """
    
class _PacketSourceBlacklist(_PacketRejection):
    """
    Indicates that the packet was added to a blacklist, based on this event.
    """
    