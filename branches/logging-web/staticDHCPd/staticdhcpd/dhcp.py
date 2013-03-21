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
 
 (C) Neil Tallim, 2009 <red.hamsterx@gmail.com>
"""
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

_logger = logging.getLogger('dhcp')

def _logInvalidValue(name, value, subnet, serial):
    _logger.error("Invalid value for %(subnet)s:%(serial)i:%(name)s: %(value)s" % {
        'subnet': subnet,
        'serial': serial,
        'name': name,
        'value': value,
    })
    
class _DHCPServer(libpydhcpserver.dhcp_network.DHCPNetwork):
    """
    The handler that responds to all received DHCP requests.
    """
    _lock = None #: A lock used to ensure synchronous access to internal structures.
    _dhcp_assignments = None #: The MACs and the number of DHCP "leases" granted to each since the last polling interval.
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
        self._dhcp_assignments = {}
        self._ignored_addresses = []
        
        libpydhcpserver.dhcp_network.DHCPNetwork.__init__(
            self, server_address, server_port, client_port, pxe_port
        )
        
    def _addToTempBlacklist(self, mac, reason, packet_type):
        """
        Marks a MAC as ignorable for a nominal amount of time.
        
        @type mac: basestring
        @param mac: The MAC to be ignored.
        @type reason: basestring
        @param reason: The reason for ignoring the MAC.
        @type packet_type: basestring
        @param packet_type: The type of packet being ignored.
        """
        _logger.warn('%(mac)s %(reason)s; ignoring for %(time)i seconds' % {
            'mac': mac,
            'reason': reason,
            'time': config.UNAUTHORIZED_CLIENT_TIMEOUT,
        })
        with self._lock:
            self._ignored_addresses.append([mac, config.UNAUTHORIZED_CLIENT_TIMEOUT])
            
        self._logDiscardedPacket(packet_type)
        
    def _evaluateAbuse(self, mac, packet_type):
        """
        Determines whether the MAC is, or should be, blacklisted.
        
        @type mac: basestring
        @param mac: The MAC to be evaluated.
        @type packet_type: basestring
        @param packet_type: The type of packet being evaluated.
        
        @rtype: bool
        @return: True if the MAC should be ignored.
        """
        with self._lock:
            ignored = [None for (ignored_mac, timeout) in self._ignored_addresses if mac == ignored_mac]:
        if ignored:
            self._logDiscardedPacket(packet_type)
            return True
            
        if not self._logDHCPAccess(mac):
            self._logDiscardedPacket(packet_type)
            return True
            
        return False
        
    def _evaluateRelay(self, packet, pxe):
        """
        Determines whether the received packet belongs to a relayed request or
        not and decides whether it should be allowed based on policy.
        
        @type packet: L{libpydhcpserver.dhcp_packet.DHCPPacket}
        @param packet: The packet to be evaluated.
        @type pxe: bool
        @param pxe: Whether the request is PXE
        """
        giaddr = self._extractIPOrNone(packet, "giaddr")
        if giaddr: #Relayed request.
            if not config.ALLOW_DHCP_RELAYS: #Ignore it.
                _logger.warn('Relayed request from relay %(ip)s ignored' % {
                    'ip': '.'.join(map(str, giaddr)),
                })
                return False
            elif config.ALLOWED_DHCP_RELAYS and not '.'.join(map(str, giaddr)) in config.ALLOWED_DHCP_RELAYS:
                _logger.warn('Relayed request from unauthorized relay %(ip)s ignored' % {
                    'ip': '.'.join(map(str, giaddr)),
                })
                return False
        elif not config.ALLOW_LOCAL_DHCP and not pxe: #Local request, but denied.
            _logger.warn('Relayed request from relay %(ip)s ignored' % {
                'ip': '.'.join(map(str, giaddr)),
            })
            return False
        return True
        
    def _extractIPOrNone(self, packet, parameter, as_tuple=False):
        """
        Extracts the identified IP and returns it if it is defined, None otherwise.
        
        @type packet: L{libpydhcpserver.dhcp_packet.DHCPPacket}
        @param packet: The packet to be evaluated.
        @type parameter: basestring
        @param parameter: The parameter to be extracted.
        @type as_tuple: bool
        @param as_tuple: True if the result should be converted to a tuple,
            rather than being left as a list, if not None.
            
        @rtype: list|tuple|NoneType
        @return: The requested IP.
        """
        addr = packet.getOption(parameter)
        if not addr or not any(addr):
            return None
            
        if as_tuple:
            return tuple(addr)
        return addr
        
    def _handleDHCPDecline(self, packet, source_address, pxe):
        """
        Informs the operator of a potential IP collision on the network.
        
        This function checks to make sure the MAC isn't ignored or acting
        maliciously, then checks the database to see whether it has an assigned
        IP. If it does, and the IP it thinks it has a right to matches this IP,
        then a benign message is logged and the operator is informed; if not,
        the decline is flagged as a malicious act.
        
        @type packet: L{libpydhcpserver.dhcp_packet.DHCPPacket}
        @param packet: The DHCPDISCOVER to be evaluated.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        _logger.debug('Received DECLINE')
        if not self._evaluateRelay(packet, pxe):
            return
            
        start_time = time.time()
        try:
            mac = packet.getHardwareAddress()
            if self._evaluateAbuse(mac, 'DECLINE'):
                return
                
            _logger.info('DECLINE from %(mac)s' % {
                'mac': mac,
            })
            
            ip = self._extractIPOrNone(packet, "requested_ip_address")
            if not ip:
                self._addToTempBlacklist(mac, "sent DECLINE without indicating the conflicting IP", "DECLINE")
                return
                
            server_identifier = self._extractIPOrNone(packet, "server_identifier")
            if not server_identifier:
                self._addToTempBlacklist(mac, "DECLINE without a server-identifier", "DECLINE")
                return
                
            if '.'.join(map(str, server_identifier)) == self._server_address: #Rejected!
                result = system.DATABASE.lookupMAC(mac) or config.handleUnknownMAC(
                    packet, "DECLINE",
                    mac, tuple(ip), self._extractIPOrNone(packet, "giaddr", as_tuple=True),
                    pxe and packet.extractPXEOptions(), packet.extractVendorOptions()
                )
                ip = '.'.join(map(str, ip))
                if result and result[0] == ip: #Known client.
                    _logger.error('DECLINE from %(mac)s for %(ip)s on (%(subnet)s, %(serial)i)' % {
                        'ip': ip,
                        'mac': mac,
                        'subnet': result[9],
                        'serial': result[10],
                    })
                    return
                else:
                    _logger.warn('Misconfigured client %(mac)s sent DECLINE for %(ip)s' % {
                        'ip': ip,
                        'mac': mac,
                    })
            self._logDiscardedPacket('DECLINE')
        finally:
            self._logTimeTaken(time.time() - start_time)
            
    def _handleDHCPDiscover(self, packet, source_address, pxe):
        """
        Evaluates a DHCPDISCOVER request from a client and determines whether a
        DHCPOFFER should be sent.
        
        The logic here is to make sure the MAC isn't ignored or acting
        maliciously, then check the database to see whether it has an assigned
        IP. If it does, that IP is offered, along with all relevant options; if
        not, the MAC is ignored to mitigate spam from follow-up DHCPDISCOVERS.
        
        @type packet: L{libpydhcpserver.dhcp_packet.DHCPPacket}
        @param packet: The DHCPDISCOVER to be evaluated.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        _logger.debug('Received DISCOVER')
        if not self._evaluateRelay(packet, pxe):
            return
            
        start_time = time.time()
        try:
            mac = packet.getHardwareAddress()
            if self._evaluateAbuse(mac, 'DISCOVER'):
                return
                
            _logger.info('DISCOVER from %(mac)s' % {
             'mac': mac,
            })
            
            try:
                giaddr = self._extractIPOrNone(packet, "giaddr", as_tuple=True)
                pxe_options = packet.extractPXEOptions()
                vendor_options = packet.extractVendorOptions()
                result = system.DATABASE.lookupMAC(mac) or config.handleUnknownMAC(
                 packet, "DISCOVER",
                 mac, None, giaddr,
                 pxe and pxe_options, vendor_options
                )
                if result:
                    rapid_commit = not packet.getOption('rapid_commit') is None
                    if rapid_commit:
                        packet.transformToDHCPAckPacket()
                        packet.forceOption('rapid_commit', [])
                    else:
                        packet.transformToDHCPOfferPacket()
                        
                    self._loadDHCPPacket(packet, result)
                    if config.loadDHCPPacket(
                     packet,
                     mac, tuple(ipToList(result[0])), giaddr,
                     result[9], result[10],
                     pxe and pxe_options, vendor_options
                    ):
                        if rapid_commit:
                            self._sendDHCPPacket(packet, source_address, 'ACK-rapid', mac, result[0], pxe)
                        else:
                            self._sendDHCPPacket(packet, source_address, 'OFFER', mac, result[0], pxe)
                        return
                    else:
                        self._logIgnoredPacket(mac, 'DISCOVER')
                        return
                else:
                    if config.AUTHORITATIVE:
                        packet.transformToDHCPNackPacket()
                        self._sendDHCPPacket(packet, source_address, 'NAK', mac, '?.?.?.?', pxe)
                        return
                    else:
                        self._addToTempBlacklist(mac, "is unknown", "DISCOVER")
                        return
            except Exception:
                _logger.critical("Unable to respond to '%(mac)s':\n%(error)s"  % {'mac': mac, 'error': traceback.format_exc()})
        finally:
            self._logTimeTaken(time.time() - start_time)
            
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
        _logger.debug('Received LEASEQUERY')
        if not self._evaluateRelay(packet, pxe):
            return
            
        start_time = time.time()
        try:
            mac = packet.getHardwareAddress()
            if self._evaluateAbuse(mac, 'LEASEQUERY'):
                return
                
            _logger.info('LEASEQUERY from %(mac)s' % {
             'mac': mac,
            })
            
            self._logDiscardedPacket('LEASEQUERY')
        finally:
            self._logTimeTaken(time.time() - start_time)
            
    def _handleDHCPRequest(self, packet, source_address, pxe):
        """
        Evaluates a DHCPREQUEST request from a client and determines whether a
        DHCPACK should be sent.
        
        The logic here is to make sure the MAC isn't ignored or acting
        maliciously, then check the database to see whether it has an assigned
        IP. If it does, and the IP it thinks it has a right to matches this IP,
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
        _logger.debug('Received REQUEST')
        if not self._evaluateRelay(packet, pxe):
            return
            
        start_time = time.time()
        try:
            mac = packet.getHardwareAddress()
            if self._evaluateAbuse(mac, 'REQUEST'):
                return
                
            ip = self._extractIPOrNone(packet, "requested_ip_address", as_tuple=True)
            sid = self._extractIPOrNone(packet, "server_identifier")
            ciaddr = self._extractIPOrNone(packet, "ciaddr")
            giaddr = self._extractIPOrNone(packet, "giaddr", as_tuple=True)
            s_ip = ip and '.'.join(map(str, ip))
            s_sid = sid and '.'.join(map(str, sid))
            s_ciaddr = ciaddr and '.'.join(map(str, ciaddr))
            
            pxe_options = packet.extractPXEOptions()
            vendor_options = packet.extractVendorOptions()
            
            if sid and not ciaddr: #SELECTING
                if s_sid == self._server_address: #Chosen!
                    _logger.info('REQUEST:SELECTING from %(mac)s' % {
                     'mac': mac,
                    })
                    try:
                        result = system.DATABASE.lookupMAC(mac) or config.handleUnknownMAC(
                         packet, "SELECTING",
                         mac, ip, giaddr,
                         pxe and pxe_options, vendor_options
                        )
                        if result and (not ip or result[0] == s_ip):
                            packet.transformToDHCPAckPacket()
                            self._loadDHCPPacket(packet, result)
                            if config.loadDHCPPacket(
                             packet,
                             mac, tuple(ipToList(result[0])), giaddr,
                             result[9], result[10],
                             pxe and pxe_options, vendor_options
                            ):
                                self._sendDHCPPacket(packet, source_address, 'ACK', mac, s_ip, pxe)
                            else:
                                self._logIgnoredPacket(mac, 'REQUEST:SELECTING')
                                return
                        else:
                            packet.transformToDHCPNackPacket()
                            self._sendDHCPPacket(packet, source_address, 'NAK', mac, 'NO-MATCH', pxe)
                    except Exception:
                        _logger.critical("Unable to respond to '%(mac)s':\n%(error)s"  % {'mac': mac, 'error': traceback.format_exc()})
                else:
                    self._logDiscardedPacket('REQUEST:SELECTING')
            elif not sid and not ciaddr and ip: #INIT-REBOOT
                _logger.info('REQUEST:INIT-REBOOT from %(mac)s' % {
                 'mac': mac,
                })
                try:
                    result = system.DATABASE.lookupMAC(mac) or config.handleUnknownMAC(
                     packet, "INIT-REBOOT",
                     mac, ip, giaddr,
                     pxe and pxe_options, vendor_options
                    )
                    if result and result[0] == s_ip:
                        packet.transformToDHCPAckPacket()
                        self._loadDHCPPacket(packet, result)
                        if config.loadDHCPPacket(
                         packet,
                         mac, tuple(ip), giaddr,
                         result[9], result[10],
                         pxe and pxe_options, vendor_options
                        ):
                            self._sendDHCPPacket(packet, source_address, 'ACK', mac, s_ip, pxe)
                        else:
                            self._logIgnoredPacket(mac, 'REQUEST:INIT-REBOOT')
                            return
                    else:
                        packet.transformToDHCPNackPacket()
                        self._sendDHCPPacket(packet, source_address, 'NAK', mac, s_ip, pxe)
                except Exception:
                    _logger.critical("Unable to respond to '%(mac)s':\n%(error)s"  % {'mac': mac, 'error': traceback.format_exc()})
            elif not sid and ciaddr and not ip: #RENEWING or REBINDING
                if config.NAK_RENEWALS and not pxe:
                    packet.transformToDHCPNackPacket()
                    self._sendDHCPPacket(packet, source_address, 'NAK', mac, 'NAK_RENEWALS', pxe)
                else:
                    renew = source_address[0] not in ('255.255.255.255', '0.0.0.0', '')
                    _logger.info('REQUEST:%(mode)s from %(mac)s' % {
                     'mac': mac,
                     'mode': renew and 'RENEW' or 'REBIND',
                    })
                    
                    try:
                        result = system.DATABASE.lookupMAC(mac) or config.handleUnknownMAC(
                         packet, renew and "RENEW" or "REBIND",
                         mac, ip, giaddr,
                         pxe and pxe_options, vendor_options
                        )
                        if result and result[0] == s_ciaddr:
                            packet.transformToDHCPAckPacket()
                            packet.setOption('yiaddr', ciaddr)
                            self._loadDHCPPacket(packet, result)
                            if config.loadDHCPPacket(
                             packet,
                             mac, tuple(ciaddr), giaddr,
                             result[9], result[10],
                             pxe and pxe_options, vendor_options
                            ):
                                self._sendDHCPPacket(packet, (s_ciaddr, 0), 'ACK', mac, s_ciaddr, pxe)
                            else:
                                self._logIgnoredPacket(mac, renew and "RENEW" or "REBIND")
                                return
                        else:
                            if renew:
                                packet.transformToDHCPNackPacket()
                                self._sendDHCPPacket(packet, (s_ciaddr, 0), 'NAK', mac, s_ciaddr, pxe)
                            else:
                                self._logDiscardedPacket('REQUEST:REBIND')
                    except Exception:
                        _logger.critical("Unable to respond to '%(mac)s':\n%(error)s"  % {'mac': mac, 'error': traceback.format_exc()})
            else:
                _logger.warn('REQUEST:UNKNOWN (%(sid)s %(ciaddr)s %(ip)s) from %(mac)s' % {
                 'sid': str(sid),
                 'ciaddr': str(ciaddr),
                 'ip': str(ip),
                 'mac': mac,
                })
                self._logDiscardedPacket('REQUEST')
        finally:
            self._logTimeTaken(time.time() - start_time)
            
    def _handleDHCPInform(self, packet, source_address, pxe):
        """
        Evaluates a DHCPINFORM request from a client and determines whether a
        DHCPACK should be sent.
        
        The logic here is to make sure the MAC isn't ignored or acting
        maliciously, then check the database to see whether it has an assigned
        IP. If it does, and the IP it thinks it has a right to matches this IP,
        then an ACK is sent, along with all relevant options; if not, the
        request is ignored.
        
        @type packet: L{libpydhcpserver.dhcp_packet.DHCPPacket}
        @param packet: The DHCPREQUEST to be evaluated.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        _logger.debug('Received INFORM')
        if not self._evaluateRelay(packet, pxe):
            return
            
        start_time = time.time()
        try:
            mac = packet.getHardwareAddress()
            if self._evaluateAbuse(mac, 'INFORM'):
                return
                
            _logger.info('INFORM from %(mac)s' % {
                'mac': mac,
            })
            
            ciaddr = self._extractIPOrNone(packet, "ciaddr")
            giaddr = self._extractIPOrNone(packet, "giaddr", as_tuple=True)
            
            if not ciaddr:
                self._addToTempBlacklist(mac, "sent malformed packet", "INFORM")
                return
                
            try:
                pxe_options = packet.extractPXEOptions()
                vendor_options = packet.extractVendorOptions()
                result = system.DATABASE.lookupMAC(mac) or config.handleUnknownMAC(
                    packet, "INFORM",
                    mac, ciaddr, giaddr,
                    pxe and pxe_options, vendor_options
                )
                if result:
                    packet.transformToDHCPAckPacket()
                    self._loadDHCPPacket(packet, result, True)
                    if config.loadDHCPPacket(
                        packet,
                        mac, tuple(ipToList(result[0])), giaddr,
                        result[9], result[10],
                        pxe and pxe_options, vendor_options
                    ):
                        self._sendDHCPPacket(
                            packet,
                            source_address, 'ACK', mac, ciaddr and '.'.join(map(str, ciaddr)) or '0.0.0.0',
                            pxe
                        )
                    else:
                        self._logIgnoredPacket(mac, 'INFORM')
                        return
                else:
                    self._addToTempBlacklist(mac, "is unknown", "INFORM")
                    return
            except Exception:
                _logger.critical("Unable to respond to '%(mac)s':\n%(error)s"  % {'mac': mac, 'error': traceback.format_exc()})
        finally:
            self._logTimeTaken(time.time() - start_time)
            
    def _handleDHCPRelease(self, packet, source_address, pxe):
        """
        Informs the DHCP operator that a client has terminated its "lease".
        
        This function checks to make sure the MAC isn't ignored or acting
        maliciously, then checks the database to see whether it has an assigned
        IP. If it does, and the IP it thinks it has a right to matches this IP,
        then a benign message is logged; if not, the release is flagged as
        a malicious act.
        
        @type packet: L{libpydhcpserver.dhcp_packet.DHCPPacket}
        @param packet: The DHCPDISCOVER to be evaluated.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        _logger.debug('Received RELEASE')
        if not self._evaluateRelay(packet, pxe):
            return
            
        start_time = time.time()
        try:
            mac = packet.getHardwareAddress()
            if self._evaluateAbuse(mac, 'RELEASE'):
                return
                
            _logger.info('RELEASE from %(mac)s' % {
             'mac': mac,
            })
            
            s_id = self._extractIPOrNone(packet, "server_identifier")
            if not s_id:
                self._addToTempBlacklist(mac, "sent RELEASE without a server-identifier", "RELEASE")
                return
                
            if '.'.join(map(str, s_id)) == self._server_address: #Released!
                ip = self._extractIPOrNone(packet, "ciaddr", as_tuple=True)
                
                result = system.DATABASE.lookupMAC(mac) or config.handleUnknownMAC(
                    packet, "RELEASE",
                    mac, ip, self._extractIPOrNone(packet, "giaddr", as_tuple=True),
                    pxe and packet.extractPXEOptions(), packet.extractVendorOptions()
                )
                ip = '.'.join(map(str, ip))
                if result and result[0] == ip: #Known client.
                    _logger.info('RELEASE from %(mac)s for %(ip)s' % {
                        'ip': ip,
                        'mac': mac,
                    })
                    return
                else:
                    _logger.warn('Misconfigured client %(mac)s sent RELEASE for %(ip)s' % {
                        'ip': ip,
                        'mac': mac,
                    })
            self._logDiscardedPacket('RELEASE')
        finally:
            self._logTimeTaken(time.time() - start_time)
            
    def _loadDHCPPacket(self, packet, result, inform=False):
        """
        Sets DHCP option fields based on values returned from the database.
        
        @type packet: L{libpydhcpserver.dhcp_packet.DHCPPacket}
        @param packet: The packet being updated.
        @type result: tuple(11)
        @param result: The value returned from the database or surrogate source.
        @type inform: bool
        @param inform: True if this is a response to a DHCPINFORM message.
        """
        (ip, hostname,
         gateway, subnet_mask, broadcast_address,
         domain_name, domain_name_servers, ntp_servers,
         lease_time, subnet, serial) = result
        
        #Core parameters.
        if not inform:
            if not packet.setOption('yiaddr', ipToList(ip)):
                _logInvalidValue('ip', ip, subnet, serial)
            if not packet.setOption('ip_address_lease_time', longToList(int(lease_time))):
                _logInvalidValue('lease_time', lease_time, subnet, serial)
                
        #Default gateway, subnet mask, and broadcast address.
        if gateway:
            if not packet.setOption('router', ipToList(gateway)):
                _logInvalidValue('gateway', gateway, subnet, serial)
        if subnet_mask:
            if not packet.setOption('subnet_mask', ipToList(subnet_mask)):
                _logInvalidValue('subnet_mask', subnet_mask, subnet, serial)
        if broadcast_address:
            if not packet.setOption('broadcast_address', ipToList(broadcast_address)):
                _logInvalidValue('broadcast_address', broadcast_address, subnet, serial)
                
        #Domain details.
        if hostname:
            if not packet.setOption('hostname', strToList(hostname)):
                _logInvalidValue('hostname', hostname, subnet, serial)
        if domain_name:
            if not packet.setOption('domain_name', strToList(domain_name)):
                _logInvalidValue('domain_name', domain_name, subnet, serial)
        if domain_name_servers:
            if not packet.setOption('domain_name_servers', ipsToList(domain_name_servers)):
                _logInvalidValue('domain_name_servers', domain_name_servers, subnet, serial)
                
        #NTP servers.
        if ntp_servers:
            if not packet.setOption('ntp_servers', ipsToList(ntp_servers)):
                _logInvalidValue('ntp_servers', ntp_servers, subnet, serial)
                
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
                assignments = self._dhcp_assignments.get(mac)
                if not assignments:
                    self._dhcp_assignments[mac] = 1
                else:
                    self._dhcp_assignments[mac] += 1
                    if assignments + 1 > config.SUSPEND_THRESHOLD:
                        _logger.warn('%(mac)s issuing too many requests; ignoring for %(time)i seconds' % {
                         'mac': mac,
                         'time': config.MISBEHAVING_CLIENT_TIMEOUT,
                        })
                        self._ignored_addresses.append([mac, config.MISBEHAVING_CLIENT_TIMEOUT])
                        return False
        return True
        
    def _logDiscardedPacket(self, packet_type):
        """
        Increments the number of packets discarded.
        """
        _logger.debug("Discarded packet of type %(type)s" % {'type': packet_type,})
        #TODO
        #with self._stats_lock:
        #    self._packets_discarded += 1
        
    def _logIgnoredPacket(self, mac, packet_type):
        """
        A very common logging operation.
        """
        _logger.info('Ignoring %(mac)s per loadDHCPPacket()' % {
         'mac': mac,
        })
        self._logDiscardedPacket(packet_type)
        
    def _logTimeTaken(self, time_taken):
        """
        Records the time taken to process a packet.
        
        @type time_taken: float
        @param time_taken: The number of seconds the request took.
        """
        _logger.debug("Request processed in %(seconds).4fs" % {'seconds': time_taken,})
        system.STATISTICS_DHCP.trackProcessingTime(time_taken)
        
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
            giaddr = self._extractIPOrNone(packet, "giaddr")
            if giaddr: #Relayed request.
                ip = '.'.join(map(str, giaddr))
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
        
    def getNextDHCPPacket(self):
        """
        Listens for a DHCP packet and initiates processing upon receipt.
        """
        if not self._getNextDHCPPacket():
            system.STATISTICS_DHCP.trackOtherPacket()
            
    def tick(self):
        """
        Cleans up the MAC blacklist.
        """
        with self._lock:
            for i in reversed(xrange(len(self._ignored_addresses))):
                ignored_address = self._ignored_addresses[i]
                if ignored_address[1] <= 1:
                    del self._ignored_addresses[i]
                else:
                    ignored_address[1] -= 1
                    
                    
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
        