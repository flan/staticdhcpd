# pydhcplib
# Copyright (C) 2008 Mathieu Ignacio -- mignacio@april.org
#
# This file is part of pydhcplib.
# Pydhcplib is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import sys
import socket
import select
import threading

import dhcp_packet

class DhcpNetwork:
    def __init__(self, listen_address, listen_port, emit_port):

        self.listen_port = listen_port
        self.emit_port = emit_port
        self.listen_address = listen_address
        
        self.dhcp_socket = None
        self.response_socket = None
        
    # Networking stuff
    def CreateSocket(self) :
        try :
            self.response_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.dhcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error, msg :
            sys.stderr.write('pydhcplib.DhcpNetwork socket creation error : '+str(msg))

        try :
            self.response_socket.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        except socket.error, msg :
            sys.stderr.write('pydhcplib.DhcpNetwork socket error in setsockopt SO_BROADCAST : '+str(msg))

        try : 
            self.dhcp_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        except socket.error, msg :
            sys.stderr.write('pydhcplib.DhcpNetwork socket error in setsockopt SO_REUSEADDR : '+str(msg))
            
    def BindToAddress(self) :
        try :
            self.response_socket.bind((self.listen_address, 0))
            self.dhcp_socket.bind(('', self.listen_port))
        except socket.error,msg :
            sys.stderr.write( 'pydhcplib.DhcpNetwork.BindToAddress error : '+str(msg))
            exit(1)


    def GetNextDhcpPacket(self,timeout=60):
        data =""


        while data == "" :
            
            data_input,data_output,data_except = select.select([self.dhcp_socket],[],[],timeout)

            if( data_input != [] ) : (data,source_address) = self.dhcp_socket.recvfrom(2048)
            else : return None
            
            if data != "" :
                packet = dhcp_packet.DhcpPacket()
                packet.source_address = source_address
                packet.DecodePacket(data)
                
                if packet.IsDhcpDiscoverPacket():
                    threading.Thread(target=self.HandleDhcpDiscover, args=(packet,)).start()
                elif packet.IsDhcpRequestPacket():
                    threading.Thread(target=self.HandleDhcpRequest, args=(packet,)).start()
                #elif packet.IsDhcpDeclinePacket():
                #    self.HandleDhcpDecline(packet)
                #elif packet.IsDhcpReleasePacket():
                #    self.HandleDhcpRelease(packet)
                #elif packet.IsDhcpInformPacket():
                #    self.HandleDhcpInform(packet)
                    
                return packet
                
    def SendDhcpPacketTo(self, packet, _ip, _port=None):
        return self.response_socket.sendto(packet.EncodePacket(), (_ip, _port or self.emit_port))

    # Server side Handle methods
    def HandleDhcpDiscover(self, packet):
        pass

    def HandleDhcpRequest(self, packet):
        pass

    def HandleDhcpDecline(self, packet):
        pass

    def HandleDhcpRelease(self, packet):
        pass

    def HandleDhcpInform(self, packet):
        pass
        