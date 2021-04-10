# -*- encoding: utf-8 -*-
import select
import threading
import traceback

import libpydhcpserver.dhcp
from libpydhcpserver.dhcp_types.ipv4 import IPv4
from libpydhcpserver.dhcp_types.mac import MAC

_HARDCODED_MACS_TO_IPS = {
    MAC('00:11:22:33:44:55'): IPv4('192.168.0.100'),
    MAC('08:00:27:2c:45:8b'): IPv4('192.168.0.143'),
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
        
        if sid and not ciaddr: #SELECTING
            mac = packet.getHardwareAddress()
            ip = _HARDCODED_MACS_TO_IPS.get(mac)
            
            if ip and sid == self._server_address: #our offer was chosen
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
        IPv4('192.168.0.206'), #the address on which you want to listen for traffic
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
