# -*- encoding: utf-8 -*-
"""
staticDHCPd module: src.dhcp

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
import select
import threading
import time

import src.conf_buffer as conf
import src.logging
import src.sql

import libpydhcpserver.dhcp_network
from libpydhcpserver.type_rfc import (
 ipToList, ipsToList,
 intToList, intsToList,
 longToList, longsToList,
 strToList,
)

_dhcp_servers = [] #: A collection of all instantiated DHCP servers; this should only ever be one element long.
def flushCache():
    """
    Flushes all cached DHCP data.
    """
    for dhcp_server in _dhcp_servers:
        dhcp_server.flushCache()
        
def _logInvalidValue(name, value, subnet, serial):
    src.logging.writeLog("Invalid value for %(subnet)s:%(serial)i:%(name)s: %(value)s" % {
     'subnet': subnet,
     'serial': serial,
     'name': name,
     'value': value,
    })
    
class _DHCPServer(libpydhcpserver.dhcp_network.DHCPNetwork):
    """
    The handler that responds to all received DHCP requests.
    """
    _sql_broker = None #: The SQL broker to be used when handling MAC lookups.
    
    _stats_lock = None #: A lock used to ensure synchronous access to performance statistics.
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
        self._stats_lock = threading.Lock()
        self._dhcp_assignments = {}
        self._ignored_addresses = []
        
        libpydhcpserver.dhcp_network.DHCPNetwork.__init__(
         self, server_address, server_port, client_port, pxe_port
        )
        
        self._sql_broker = src.sql.SQL_BROKER()
        
    def _evaluateRelay(self, packet):
        """
        Determines whether the received packet belongs to a relayed request or
        not and decides whether it should be allowed based on policy.
        
        @type packet: L{libpydhcpserver.dhcp_packet.DHCPPacket}
        @param packet: The packet to be evaluated.
        """
        giaddr = packet.getOption("giaddr")
        if not giaddr == [0,0,0,0]: #Relayed request.
            if not conf.ALLOW_DHCP_RELAYS: #Ignore it.
                return False
            elif conf.ALLOWED_DHCP_RELAYS and not '.'.join(map(str, giaddr)) in conf.ALLOWED_DHCP_RELAYS:
                src.logging.writeLog('Relayed request from unauthorized relay %(ip)s ignored' % {
                 'ip': '.'.join(map(str, giaddr)),
                })
                return False
        elif not conf.ALLOW_LOCAL_DHCP: #Local request, but denied.
            return False
        return True
        
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
        if not self._evaluateRelay(packet):
            return
            
        start_time = time.time()
        mac = packet.getHardwareAddress()
        if not [None for (ignored_mac, timeout) in self._ignored_addresses if mac == ignored_mac]:
            if not self._logDHCPAccess(mac):
                self._logDiscardedPacket()
                return
                
            if '.'.join(map(str, packet.getOption("server_identifier"))) == self._server_address: #Rejected!
                ip = '.'.join(map(str, packet.getOption("requested_ip_address")))
                result = self._sql_broker.lookupMAC(mac)
                if result and result[0] == ip: #Known client.
                    src.logging.writeLog('DHCPDECLINE from %(mac)s for %(ip)s on (%(subnet)s, %(serial)i)' % {
                     'ip': ip,
                     'mac': mac,
                     'subnet': result[9],
                     'serial': result[10],
                    })
                    src.logging.sendDeclineReport(mac, ip, result[9], result[10])
                else:
                    src.logging.writeLog('Misconfigured client %(mac)s sent DHCPDECLINE for %(ip)s' % {
                     'ip': ip,
                     'mac': mac,
                    })
            else:
                self._logDiscardedPacket()
        else:
            self._logDiscardedPacket()
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
        if not self._evaluateRelay(packet):
            return
            
        start_time = time.time()
        mac = packet.getHardwareAddress()
        if not [None for (ignored_mac, timeout) in self._ignored_addresses if mac == ignored_mac]:
            if not self._logDHCPAccess(mac):
                self._logDiscardedPacket()
                return
                
            src.logging.writeLog('DHCPDISCOVER from %(mac)s' % {
             'mac': mac,
            })
            
            try:
                result = self._sql_broker.lookupMAC(mac)
                if result:
                    rapid_commit = not packet.getOption('rapid_commit') is None
                    if rapid_commit:
                        packet.transformToDHCPAckPacket()
                        packet.forceOption('rapid_commit', [])
                    else:
                        packet.transformToDHCPOfferPacket()
                    vendor_options = packet.extractVendorOptions()
                        
                    self._loadDHCPPacket(packet, result)
                    giaddr = packet.getOption("giaddr")
                    if not giaddr or giaddr == [0,0,0,0]:
                        giaddr = None
                    else:
                        giaddr = tuple(giaddr)
                    if conf.loadDHCPPacket(
                     packet,
                     mac, tuple(ipToList(result[0])), giaddr,
                     result[9], result[10],
                     pxe, vendor_options
                    ):
                        if rapid_commit:
                            self._sendDHCPPacket(packet, source_address, 'ACK-rapid', mac, result[0])
                        else:
                            self._sendDHCPPacket(packet, source_address, 'OFFER', mac, result[0])
                    else:
                        src.logging.writeLog('Ignoring %(mac)s per loadDHCPPacket()' % {
                         'mac': mac,
                        })
                        self._logDiscardedPacket()
                else:
                    if conf.AUTHORITATIVE:
                        packet.transformToDHCPNackPacket()
                        self._sendDHCPPacket(packet, source_address, 'NAK', mac, '?.?.?.?')
                    else:
                        src.logging.writeLog('%(mac)s unknown; ignoring for %(time)i seconds' % {
                         'mac': mac,
                         'time': conf.UNAUTHORIZED_CLIENT_TIMEOUT,
                        })
                        self._stats_lock.acquire()
                        self._ignored_addresses.append([mac, conf.UNAUTHORIZED_CLIENT_TIMEOUT])
                        self._stats_lock.release()
            except Exception, e:
                src.logging.sendErrorReport('Unable to respond to %(mac)s' % {'mac': mac,}, e)
        else:
            self._logDiscardedPacket()
        self._logTimeTaken(time.time() - start_time)
        
    def _handleDHCPLeaseQuery(self, packet, source_address, pxe):
        """
        Evaluates a DHCPLEASEQUERY request from a relay and determines whether
        a DHCPLEASEACTIVE or DHCPLEASEUNKNOWN should be sent.
        
        The logic here is to make sure the MAC isn't ignored or acting
        maliciously, then check the database to see whether it has an assigned
        IP. If it does, DHCPLEASEACTIVE is sent. Otherwise, DHCPLEASEUNKNOWN is
        sent.
        
        @type packet: L{libpydhcpserver.dhcp_packet.DHCPPacket}
        @param packet: The DHCPREQUEST to be evaluated.
        @type source_address: tuple
        @param source_address: The address (host, port) from which the request
            was received.
        @type pxe: bool
        @param pxe: True if the packet was received on the PXE port.
        """
        if not self._evaluateRelay(packet):
            return
            
        start_time = time.time()
        mac = None
        try:
            mac = packet.getHardwareAddress()
        except:
            pass
        if not mac: #IP/client-ID-based lookup; not supported.
            self._logDiscardedPacket()
            return
            
        if not [None for (ignored_mac, timeout) in self._ignored_addresses if mac == ignored_mac]:
            if not self._logDHCPAccess(mac):
                self._logDiscardedPacket()
                return
                
            src.logging.writeLog('DHCPLEASEQUERY for %(mac)s' % {
             'mac': mac,
            })
            
            try:
                result = self._sql_broker.lookupMAC(mac)
                if result:
                    packet.transformToDHCPLeaseActivePacket()
                    if packet.setOption('yiaddr', ipToList(result[0])):
                        self._sendDHCPPacket(packet, source_address, 'LEASEACTIVE', mac, result[0])
                    else:
                        _logInvalidValue('ip', result[0], result[-2], result[-1])
                else:
                    packet.transformToDHCPLeaseUnknownPacket()
                    self._sendDHCPPacket(packet, source_address, 'LEASEUNKNOWN', mac, '?.?.?.?')
            except Exception, e:
                src.logging.sendErrorReport('Unable to respond for %(mac)s' % {'mac': mac,}, e)
        else:
            self._logDiscardedPacket()
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
        if not self._evaluateRelay(packet):
            return
            
        start_time = time.time()
        mac = packet.getHardwareAddress()
        if not [None for (ignored_mac, timeout) in self._ignored_addresses if mac == ignored_mac]:
            if not self._logDHCPAccess(mac):
                self._logDiscardedPacket()
                return
                
            ip = packet.getOption("requested_ip_address")
            sid = packet.getOption("server_identifier")
            ciaddr = packet.getOption("ciaddr")
            giaddr = packet.getOption("giaddr")
            s_ip = ip and '.'.join(map(str, ip))
            s_sid = sid and '.'.join(map(str, sid))
            s_ciaddr = ciaddr and '.'.join(map(str, ciaddr))
            
            if not ip or ip == [0,0,0,0]:
                ip = None
            if not sid or sid == [0,0,0,0]:
                sid = None
            if not ciaddr or ciaddr == [0,0,0,0]:
                ciaddr = None
            if not giaddr or giaddr == [0,0,0,0]:
                giaddr = None
            else:
                giaddr = tuple(giaddr)
                
            if sid and not ciaddr: #SELECTING
                if s_sid == self._server_address: #Chosen!
                    src.logging.writeLog('DHCPREQUEST:SELECTING from %(mac)s' % {
                     'mac': mac,
                    })
                    try:
                        result = self._sql_broker.lookupMAC(mac)
                        if result and (not ip or result[0] == s_ip):
                            packet.transformToDHCPAckPacket()
                            vendor_options = packet.extractVendorOptions()
                            self._loadDHCPPacket(packet, result)
                            if conf.loadDHCPPacket(
                             packet,
                             mac, tuple(ipToList(result[0])), giaddr,
                             result[9], result[10],
                             pxe, vendor_options
                            ):
                                self._sendDHCPPacket(packet, source_address, 'ACK', mac, s_ip)
                            else:
                                src.logging.writeLog('Ignoring %(mac)s per loadDHCPPacket()' % {
                                 'mac': mac,
                                })
                                self._logDiscardedPacket()
                        else:
                            packet.transformToDHCPNackPacket()
                            self._sendDHCPPacket(packet, source_address, 'NAK', mac, 'NO-MATCH')
                    except Exception, e:
                        src.logging.sendErrorReport('Unable to respond to %(mac)s' % {'mac': mac,}, e)
                else:
                    self._logDiscardedPacket()
            elif not sid and not ciaddr and ip: #INIT-REBOOT
                src.logging.writeLog('DHCPREQUEST:INIT-REBOOT from %(mac)s' % {
                 'mac': mac,
                })
                try:
                    result = self._sql_broker.lookupMAC(mac)
                    if result and result[0] == s_ip:
                        packet.transformToDHCPAckPacket()
                        vendor_options = packet.extractVendorOptions()
                        self._loadDHCPPacket(packet, result)
                        if conf.loadDHCPPacket(
                         packet,
                         mac, tuple(ip), giaddr,
                         result[9], result[10],
                         pxe, vendor_options
                        ):
                            self._sendDHCPPacket(packet, source_address, 'ACK', mac, s_ip)
                        else:
                            src.logging.writeLog('Ignoring %(mac)s per loadDHCPPacket()' % {
                             'mac': mac,
                            })
                            self._logDiscardedPacket()
                    else:
                        packet.transformToDHCPNackPacket()
                        self._sendDHCPPacket(packet, source_address, 'NAK', mac, s_ip)
                except Exception, e:
                    src.logging.sendErrorReport('Unable to respond to %(mac)s' % {'mac': mac,}, e)
            elif not sid and ciaddr and not ip: #RENEWING or REBINDING
                if conf.NAK_RENEWALS:
                    packet.transformToDHCPNackPacket()
                    self._sendDHCPPacket(packet, source_address, 'NAK', mac, 'NAK_RENEWALS')
                else:
                    if source_address[0] not in ('255.255.255.255', '0.0.0.0', ''):
                        src.logging.writeLog('DHCPREQUEST:RENEW from %(mac)s' % {
                         'mac': mac,
                        })
                    else:
                        src.logging.writeLog('DHCPREQUEST:REBIND from %(mac)s' % {
                         'mac': mac,
                        })
                        
                    try:
                        result = self._sql_broker.lookupMAC(mac)
                        if result and result[0] == s_ciaddr:
                            packet.transformToDHCPAckPacket()
                            vendor_options = packet.extractVendorOptions()
                            packet.setOption('yiaddr', ciaddr)
                            self._loadDHCPPacket(packet, result)
                            if conf.loadDHCPPacket(
                             packet,
                             mac, tuple(ciaddr), giaddr,
                             result[9], result[10],
                             pxe, vendor_options
                            ):
                                self._sendDHCPPacket(packet, (s_ciaddr, 0), 'ACK', mac, s_ciaddr)
                            else:
                                src.logging.writeLog('Ignoring %(mac)s per loadDHCPPacket()' % {
                                 'mac': mac,
                                })
                                self._logDiscardedPacket()
                        else:
                            packet.transformToDHCPNackPacket()
                            self._sendDHCPPacket(packet, (s_ciaddr, 0), 'NAK', mac, s_ciaddr)
                    except Exception, e:
                        src.logging.sendErrorReport('Unable to respond to %(mac)s' % {'mac': mac,}, e)
            else:
                src.logging.writeLog('DHCPREQUEST:UNKNOWN (%(sid)s %(ciaddr)s %(ip)s) from %(mac)s' % {
                 'sid': str(sid),
                 'ciaddr': str(ciaddr),
                 'ip': str(ip),
                 'mac': mac,
                })
                self._logDiscardedPacket()
        else:
            self._logDiscardedPacket()
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
        if not self._evaluateRelay(packet):
            return
            
        start_time = time.time()
        mac = packet.getHardwareAddress()
        if not [None for (ignored_mac, timeout) in self._ignored_addresses if mac == ignored_mac]:
            if not self._logDHCPAccess(mac):
                self._logDiscardedPacket()
                return
                
            ciaddr = packet.getOption("ciaddr")
            giaddr = packet.getOption("giaddr")
            s_ciaddr = '.'.join(map(str, ciaddr))
            if not ciaddr or ciaddr == [0,0,0,0]:
                ciaddr = None
            if not giaddr or giaddr == [0,0,0,0]:
                giaddr = None
            else:
                giaddr = tuple(giaddr)
                
            src.logging.writeLog('DHCPINFORM from %(mac)s' % {
             'mac': mac,
            })
            
            if not ciaddr:
                src.logging.writeLog('%(mac)s sent malformed packet; ignoring for %(time)i seconds' % {
                 'mac': mac,
                 'time': conf.UNAUTHORIZED_CLIENT_TIMEOUT,
                })
                self._stats_lock.acquire()
                self._ignored_addresses.append([mac, conf.UNAUTHORIZED_CLIENT_TIMEOUT])
                self._stats_lock.release()
                self._logDiscardedPacket()
                return
                
            try:
                result = self._sql_broker.lookupMAC(mac)
                if result:
                    packet.transformToDHCPAckPacket()
                    vendor_options = packet.extractVendorOptions()
                    self._loadDHCPPacket(packet, result, True)
                    if conf.loadDHCPPacket(
                     packet,
                     mac, tuple(ipToList(result[0])), giaddr,
                     result[9], result[10],
                     pxe, vendor_options
                    ):
                        self._sendDHCPPacket(packet, source_address, 'ACK', mac, s_ciaddr)
                    else:
                        src.logging.writeLog('Ignoring %(mac)s per loadDHCPPacket()' % {
                         'mac': mac,
                        })
                        self._logDiscardedPacket()
                else:
                    src.logging.writeLog('%(mac)s unknown; ignoring for %(time)i seconds' % {
                     'mac': mac,
                     'time': conf.UNAUTHORIZED_CLIENT_TIMEOUT,
                    })
                    self._stats_lock.acquire()
                    self._ignored_addresses.append([mac, conf.UNAUTHORIZED_CLIENT_TIMEOUT])
                    self._stats_lock.release()
                    self._logDiscardedPacket()
            except Exception, e:
                src.logging.sendErrorReport('Unable to respond to %(mac)s' % {'mac': mac,}, e)
        else:
            self._logDiscardedPacket()
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
        if not self._evaluateRelay(packet):
            return
            
        start_time = time.time()
        mac = packet.getHardwareAddress()
        if not [None for (ignored_mac, timeout) in self._ignored_addresses if mac == ignored_mac]:
            if not self._logDHCPAccess(mac):
                self._logDiscardedPacket()
                return
                
            if '.'.join(map(str, packet.getOption("server_identifier"))) == self._server_address: #Released!
                ip = '.'.join(map(str, packet.getOption("ciaddr")))
                result = self._sql_broker.lookupMAC(mac)
                if result and result[0] == ip: #Known client.
                    src.logging.writeLog('DHCPRELEASE from %(mac)s for %(ip)s' % {
                     'ip': ip,
                     'mac': mac,
                    })
                else:
                    src.logging.writeLog('Misconfigured client %(mac)s sent DHCPRELEASE for %(ip)s' % {
                     'ip': ip,
                     'mac': mac,
                    })
            else:
                self._logDiscardedPacket()
        else:
            self._logDiscardedPacket()
        self._logTimeTaken(time.time() - start_time)
        
    def _loadDHCPPacket(self, packet, result, inform=False):
        """
        Sets DHCP option fields based on values returned from the database.
        
        @type packet: L{libpydhcpserver.dhcp_packet.DHCPPacket}
        @param packet: The packet being updated.
        @type result: tuple(11)
        @param result: The value returned from the SQL broker.
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
            if not packet.setOption('ip_address_lease_time', longToList(lease_time)):
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
        if conf.ENABLE_SUSPEND:
            self._stats_lock.acquire()
            try:
                assignments = self._dhcp_assignments.get(mac)
                if not assignments:
                    self._dhcp_assignments[mac] = 1
                else:
                    self._dhcp_assignments[mac] = assignments + 1
                    if assignments + 1 > conf.SUSPEND_THRESHOLD:
                        src.logging.writeLog('%(mac)s issuing too many requests; ignoring for %(time)i seconds' % {
                         'mac': mac,
                         'time': conf.MISBEHAVING_CLIENT_TIMEOUT,
                        })
                        self._ignored_addresses.append([mac, conf.MISBEHAVING_CLIENT_TIMEOUT])
                        return False
            finally:
                self._stats_lock.release()
        return True
        
    def _logDiscardedPacket(self):
        """
        Increments the number of packets discarded.
        """
        self._stats_lock.acquire()
        self._packets_discarded += 1
        self._stats_lock.release()
        
    def _logTimeTaken(self, time_taken):
        """
        Records the time taken to process a packet.
        
        @type time_taken: float
        @param time_taken: The number of seconds the request took.
        """
        self._stats_lock.acquire()
        self._time_taken += time_taken
        self._stats_lock.release()
        
    def _sendDHCPPacket(self, packet, address, response_type, mac, client_ip):
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
        
        @rtype: int
        @return: The number of bytes transmitted.
        """
        ip = port = None
        if address[0] not in ('255.255.255.255', '0.0.0.0', ''): #Unicast.
            giaddr = packet.getOption("giaddr")
            if giaddr and not giaddr == [0,0,0,0]: #Relayed request.
                ip = '.'.join(map(str, giaddr))
                port = self._server_port
            else: #Request directly from client, routed or otherwise.
                ip = address[0]
                port = self._client_port
        else: #Broadcast.
            ip = '255.255.255.255'
            port = self._client_port
            
        packet.setOption('server_identifier', ipToList(self._server_address))
        bytes = self._sendDHCPPacketTo(packet, ip, port)
        src.logging.writeLog('DHCP%(type)s sent to %(mac)s for %(client)s via %(ip)s:%(port)i [%(bytes)i bytes]' % {
             'type': response_type,
             'mac': mac,
             'client': client_ip,
             'bytes': bytes,
             'ip': ip,
             'port': port,
        })
        return bytes
        
    def flushCache(self):
        """
        Flushes the DHCP cache.
        """
        self._sql_broker.flushCache()
        
    def getNextDHCPPacket(self):
        """
        Listens for a DHCP packet and initiates processing upon receipt.
        """
        if self._getNextDHCPPacket():
            self._stats_lock.acquire()
            self._packets_processed += 1
            self._stats_lock.release()
            
    def getStats(self):
        """
        Returns the performance statistics of all operations performed since the
        last polling event, resets all counters, and updates the time left before
        ignored MACs' requests will be processed again.
        """
        self._stats_lock.acquire()
        try:
            for i in range(len(self._ignored_addresses)):
                self._ignored_addresses[i][1] -= conf.POLLING_INTERVAL
            self._ignored_addresses = [address for address in self._ignored_addresses if address[1] > 0]
            
            stats = (self._packets_processed, self._packets_discarded, self._time_taken, len(self._ignored_addresses))
            
            self._packets_processed = 0
            self._packets_discarded = 0
            self._time_taken = 0.0
            if conf.ENABLE_SUSPEND:
                self._dhcp_assignments = {}
                
            return stats
        finally:
            self._stats_lock.release()
            
            
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
        
        self._dhcp_server = _DHCPServer(
         '.'.join([str(int(o)) for o in conf.DHCP_SERVER_IP.split('.')]),
         int(conf.DHCP_SERVER_PORT),
         int(conf.DHCP_CLIENT_PORT),
         conf.PXE_PORT and int(conf.PXE_PORT)
        )
        _dhcp_servers.append(self._dhcp_server) #Add this server to the global list.
        
        src.logging.writeLog('Configured DHCP server')
        
    def run(self):
        """
        Runs the DHCP server indefinitely.
        
        In the event of an unexpected error, e-mail will be sent and processing
        will continue with the next request.
        """
        src.logging.writeLog('Running DHCP server')
        while True:
            try:
                self._dhcp_server.getNextDHCPPacket()
            except select.error:
                src.logging.writeLog('Suppressed non-fatal select() error in DHCP module')
            except Exception, e:
                src.logging.sendErrorReport('Unhandled exception', e)
                
    def pollStats(self):
        """
        Updates the performance statistics in the in-memory stats-log and
        implicitly updates the ignored MACs values.
        """
        (processed, discarded, time_taken, ignored_macs) = self._dhcp_server.getStats()
        src.logging.writePollRecord(processed, discarded, time_taken, ignored_macs)
        
