#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
"""
This is a minimal example showing how to use libpydhcpserver with well-behaved
clients.

It's entirely unsuitable for production work, but if you want to create a new
server or experiment with a network, it should give you enough to get started.

It will handle offers, renew, and rebind requests, so it should be enough to
bring a few hosts online for learning purposes.

Check the documentation for more information.
"""
import select
import traceback

import libpydhcpserver.dhcp
from libpydhcpserver.dhcp_types.ipv4 import IPv4
from libpydhcpserver.dhcp_types.mac import MAC

_HARDCODED_MACS_TO_IPS = {
    MAC('00:11:22:33:44:55'): IPv4('192.168.0.100'),
}
_SUBNET_MASK = IPv4('255.255.255.0')
_LEASE_TIME = 120 #seconds

class _DHCPServer(libpydhcpserver.dhcp.DHCPServer):
    def __init__(self, server_address, server_port, client_port, proxy_port, response_interface, response_interface_qtags, database):
        libpydhcpserver.dhcp.DHCPServer.__init__(
            self, server_address, server_port, client_port, proxy_port,
            response_interface=response_interface,
            response_interface_qtags=response_interface_qtags,
        )

    def _handleDHCPDiscover(self, packet, source_address, port):
        mac = packet.getHardwareAddress()
        ip = _HARDCODED_MACS_TO_IPS.get(mac)
        if ip:
            packet.transformToDHCPOfferPacket()
            packet.setOption('yiaddr', ip)
            packet.setOption(1, _SUBNET_MASK)
            packet.setOption(51, _LEASE_TIME)

            self._emitDHCPPacket(
                packet, source_address, port,
                mac, ip,
            )

    def _handleDHCPRequest(self, packet, source_address, port):
        sid = packet.extractIPOrNone("server_identifier")
        ciaddr = packet.extractIPOrNone("ciaddr")
        riaddr = packet.extractIPOrNone("requested_ip_address")
        
        mac = packet.getHardwareAddress()
        ip = _HARDCODED_MACS_TO_IPS.get(mac)
        
        if sid and not ciaddr: #SELECTING
            if ip and sid == self._server_address: #SELECTING; our offer was chosen
                packet.transformToDHCPAckPacket()
                packet.setOption('yiaddr', ip)
                packet.setOption(1, _SUBNET_MASK)
                packet.setOption(51, _LEASE_TIME)
                
                self._emitDHCPPacket(
                    packet, source_address, port,
                    mac, ip,
                )
        elif not sid and ciaddr and not riaddr: #RENEWING or REBINDING
            if ip and ip == ciaddr:
                packet.transformToDHCPAckPacket()
                packet.setOption('yiaddr', ip)
                packet.setOption(1, _SUBNET_MASK)
                packet.setOption(51, _LEASE_TIME)
                
                self._emitDHCPPacket(
                    packet, source_address, port,
                    mac, ip,
                )
                
    def _emitDHCPPacket(self, packet, address, port, mac, client_ip):
        packet.setOption(54, self._server_address) #server_identifier

        (bytes_sent, address) = self._sendDHCPPacket(packet, address, port)
        return bytes_sent

    def getNextDHCPPacket(self):
        (dhcp_received, source_address) = self._getNextDHCPPacket()
        print((dhcp_received, source_address))


if __name__ == '__main__':
    dhcp_server = _DHCPServer(
        IPv4('192.168.0.1'), #the address on which you want to listen for traffic
        67, #server port
        68, #client port
        None, #proxy port
        None, #specific response-interface name
        None, #qtags
        None, #database
    )
    while True:
        try:
            dhcp_server.getNextDHCPPacket()
        except select.error:
            pass #non-fatal error; occurs with some kernel configs
        except Exception:
            print("Unhandled exception:\n{}".format(traceback.format_exc()))
