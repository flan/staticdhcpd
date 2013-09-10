# -*- encoding: utf-8 -*-
"""
pydhcplib module: dhcp_network

Purpose
=======
 Processes DHCP packets.
 
Legal
=====
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
 
 (C) Neil Tallim, 2011 <red.hamsterx@gmail.com>
 (C) Matthew Boedicker, 2011 <matthewm@boedicker.org>
 (C) Mathieu Ignacio, 2008 <mignacio@april.org>
"""
import select
import socket
import threading

from dhcp_types.packet import DHCPPacket

class DHCPNetwork(object):
    """
    Handles the actual network I/O and internal packet-path-routing logic.
    """
    _server_address = None #: The IP address of the DHCP service.
    _server_port = None #: The port on which DHCP servers and relays listen in this network.
    _client_port = None #: The port on which DHCP clients listen in this network.
    _pxe_port = None #: The port on which DHCP servers listen for PXE traffic in this network.
    _dhcp_socket = None #: The socket used to receive DHCP requests.
    _response_socket = None #: The socket used to send DHCP responses. Necessary because of how Linux handles broadcast.
    _pxe_socket = None #: The socket used to receive PXE requests.
    
    def __init__(self, server_address, server_port, client_port, pxe_port):
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
        self._server_port = server_port
        self._client_port = client_port
        self._pxe_port = pxe_port
        
        self._createSockets()
        self._bindToAddress()
        
    def _bindToAddress(self):
        """
        Binds the server and response sockets so they may be used.
        
        @raise Exception: A problem occurred while binding the sockets.
        """
        try:
            self._response_socket.bind((self._server_address or '', 0))
            self._dhcp_socket.bind(('', self._server_port))
            if self._pxe_port:
                self._pxe_socket.bind(('', self._pxe_port))
        except socket.error, e:
            raise Exception('Unable to bind sockets: %(error)s' % {
             'error': str(e),
            })
            
    def _createSockets(self):
        """
        Creates and configures the server and response sockets.
        
        @raise Exception: A socket was in use or the OS doesn't support proper
            broadcast or reuse flags.
        """
        try:
            self._dhcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._response_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            if self._pxe_port:
                self._pxe_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error, msg:
            raise Exception('Unable to create socket: %(err)s' % {'err': str(msg),})
            
        try:
            self._response_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except socket.error, msg:
            raise Exception('Unable to set SO_BROADCAST: %(err)s' % {'err': str(msg),})
            
        try: 
            self._dhcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if self._pxe_socket:
                self._pxe_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except socket.error, msg :
            raise Exception('Unable to set SO_REUSEADDR: %(err)s' % {'err': str(msg),})
            
    def _getNextDHCPPacket(self, timeout=60):
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
        active_sockets = None
        source_address = None
        if self._pxe_socket:
            active_sockets = select.select([self._dhcp_socket, self._pxe_socket], [], [], timeout)[0]
        else:
            active_sockets = select.select([self._dhcp_socket], [], [], timeout)[0]
        if active_sockets:
            active_socket = active_sockets[0]
            (data, source_address) = active_socket.recvfrom(4096)
            if data:
                packet = DHCPPacket(data)
                if packet.isDHCPPacket():
                    pxe = active_socket == self._pxe_socket
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
        
    def _sendDHCPPacket(self, packet, ip, port, pxe):
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
        packet_encoded = packet.encodePacket()

        # When responding to a relay, the packet will be unicast, so use
        # self._dhcp_socket so the source port will be 67. Some relays
        # will not relay when the source port is not 67. Or, if PXE is in
        # use, use that socket instead.
        #
        # Otherwise use self._response_socket because it has SO_BROADCAST.
        #
        # If self._dhcp_socket is anonymously bound, the two sockets will
        # actually be one and the same, so this change has no potentially
        # damaging effects.
        ip = str(ip)
        if not ip == '255.255.255.255':
            if pxe:
                return self._pxe_socket.sendto(packet_encoded, (ip, port))
            else:
                return self._dhcp_socket.sendto(packet_encoded, (ip, port))
        else:
            return self._response_socket.sendto(packet_encoded, (ip, port))
            


"""
Use self._response_socket for both DHCP and PXE responses, writing the source-port as appropriate

Try to move most of the dhcp.py send logic here, since it's largely packet-introspection and that's
all very generally applicable to DHCP server behaviour.

References:
    UDP header: 8 bytes (source: 16, destination: 16, length: 16, checksum: 16)
    The length includes the size of the header (8 bytes)
    Checksum, from pyip:
        def cksum(s):
            if len(s) & 1:
                s = s + '\0'
            words = array.array('h', s)
            sum = 0
            for word in words:
                sum = sum + (word & 0xffff)
            hi = sum >> 16
            lo = sum & 0xffff
            sum = hi + lo
            sum = sum + (sum >> 16)
            return (~sum) & 0xffff
            
        def _assemble(self, cksum=1):
            self.ulen = 8 + len(self.data)
            begin = struct.pack('HHH', self.sport, self.dport, self.ulen)
            packet = begin + '\000\000' + self.data
            if cksum:
                self.sum = inetutils.cksum(packet)
                packet = begin + struct.pack('H', self.sum) + self.data
            self.__packet = inetutils.udph2net(packet)
            return self.__packet
            
            
            
'''
    Raw sockets on Linux
     
    Silver Moon (m00n.silv3r@gmail.com)
'''
 
# some imports
import socket, sys
from struct import *
 
# checksum functions needed for calculation checksum
def checksum(msg):
    s = 0
     
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w
     
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);
     
    #complement and mask to 4 byte short
    s = ~s & 0xffff
     
    return s
 
#create a raw socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
 
# tell kernel not to put in headers, since we are providing it, when using IPPROTO_RAW this is not necessary
# s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
     
# now start constructing the packet
packet = '';
 
source_ip = '192.168.1.101'
dest_ip = '192.168.1.1' # or socket.gethostbyname('www.google.com')
 
# ip header fields
ip_ihl = 5
ip_ver = 4
ip_tos = 0
ip_tot_len = 0  # kernel will fill the correct total length
ip_id = 54321   #Id of this packet
ip_frag_off = 0
ip_ttl = 255
ip_proto = socket.IPPROTO_TCP
ip_check = 0    # kernel will fill the correct checksum
ip_saddr = socket.inet_aton ( source_ip )   #Spoof the source ip address if you want to
ip_daddr = socket.inet_aton ( dest_ip )
 
ip_ihl_ver = (ip_ver << 4) + ip_ihl
 
# the ! in the pack format string means network order
ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
 
# tcp header fields
tcp_source = 1234   # source port
tcp_dest = 80   # destination port
tcp_seq = 454
tcp_ack_seq = 0
tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
#tcp flags
tcp_fin = 0
tcp_syn = 1
tcp_rst = 0
tcp_psh = 0
tcp_ack = 0
tcp_urg = 0
tcp_window = socket.htons (5840)    #   maximum allowed window size
tcp_check = 0
tcp_urg_ptr = 0
 
tcp_offset_res = (tcp_doff << 4) + 0
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
 
# the ! in the pack format string means network order
tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)
 
user_data = 'Hello, how are you'
 
# pseudo header fields
source_address = socket.inet_aton( source_ip )
dest_address = socket.inet_aton(dest_ip)
placeholder = 0
protocol = socket.IPPROTO_TCP
tcp_length = len(tcp_header) + len(user_data)
 
psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
psh = psh + tcp_header + user_data;
 
tcp_check = checksum(psh)
#print tcp_checksum
 
# make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)
 
# final full packet - syn packets dont have any data
packet = ip_header + tcp_header + user_data
 
#Send the packet finally - the port specified has no effect
s.sendto(packet, (dest_ip , 0 ))    # put this in a loop if you want to flood the target

"""














class L2Socket(SuperSocket):
   402     desc = "read/write packets at layer 2 using Linux PF_PACKET sockets"
   403     def __init__(self, iface = None, type = ETH_P_ALL, filter=None, nofilter=0):
   404         if iface is None:
   405             iface = conf.iface
   406         self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
   407         self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
   408         _flush_fd(self.ins)
   409         if not nofilter: 
   410             if conf.except_filter:
   411                 if filter:
   412                     filter = "(%s) and not (%s)" % (filter, conf.except_filter)
   413                 else:
   414                     filter = "not (%s)" % conf.except_filter
   415             if filter is not None:
   416                 attach_filter(self.ins, filter)
   417         self.ins.bind((iface, type))
   418         self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
   419         self.outs = self.ins
   420         self.outs.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**30)
   421         sa_ll = self.outs.getsockname()
   422         if sa_ll[3] in conf.l2types:
   423             self.LL = conf.l2types[sa_ll[3]]
   424         elif sa_ll[1] in conf.l3types:
   425             self.LL = conf.l3types[sa_ll[1]]
   426         else:
   427             self.LL = conf.default_l2
   428             warning("Unable to guess type (interface=%s protocol=%#x family=%i). Using %s" % (sa_ll[0],sa_ll[1],sa_ll[3],self.LL.name))
   429             
   430     def recv(self, x=MTU):
   431         pkt, sa_ll = self.ins.recvfrom(x)
   432         if sa_ll[2] == socket.PACKET_OUTGOING:
   433             return None
   434         try:
   435             q = self.LL(pkt)
   436         except KeyboardInterrupt:
   437             raise
   438         except:
   439             if conf.debug_dissector:
   440                 raise
   441             q = conf.raw_layer(pkt)
   442         q.time = get_last_packet_timestamp(self.ins)
   443         return q
   
   
   
   
   
   
   
class SuperSocket:
    24     __metaclass__ = _SuperSocket_metaclass
    25     desc = None
    26     closed=0
    27     def __init__(self, family=socket.AF_INET,type=socket.SOCK_STREAM, proto=0):
    28         self.ins = socket.socket(family, type, proto)
    29         self.outs = self.ins
    30         self.promisc=None
    31     def send(self, x):
    32         sx = str(x)
    33         if hasattr(x, "sent_time"):
    34             x.sent_time = time.time()
    35         return self.outs.send(sx)
    36     def recv(self, x=MTU):
    37         return conf.raw_layer(self.ins.recv(x))
    38     def fileno(self):
    39         return self.ins.fileno()
    40     def close(self):
    41         if self.closed:
    42             return
    43         self.closed=1
    44         if self.ins != self.outs:
    45             if self.outs and self.outs.fileno() != -1:
    46                 self.outs.close()
    47         if self.ins and self.ins.fileno() != -1:
    48             self.ins.close()
    49     def sr(self, *args, **kargs):
    50         return sendrecv.sndrcv(self, *args, **kargs)
    51     def sr1(self, *args, **kargs):        
    52         a,b = sendrecv.sndrcv(self, *args, **kargs)
    53         if len(a) > 0:
    54             return a[0][1]
    55         else:
    56             return None
    57     def sniff(self, *args, **kargs):
    58         return sendrecv.sniff(opened_socket=self, *args, **kargs)
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
OS X/BSD


class L2dnetSocket(SuperSocket):
   285         desc = "read/write packets at layer 2 using libdnet and libpcap"
   286         def __init__(self, iface = None, type = ETH_P_ALL, filter=None, nofilter=0):
   287             if iface is None:
   288                 iface = conf.iface
   289             self.iface = iface
   290             self.ins = open_pcap(iface, 1600, 0, 100)
   291             try:
   292                 ioctl(self.ins.fileno(),BIOCIMMEDIATE,struct.pack("I",1))
   293             except:
   294                 pass
   295             if nofilter:
   296                 if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
   297                     filter = "ether proto %i" % type
   298                 else:
   299                     filter = None
   300             else:
   301                 if conf.except_filter:
   302                     if filter:
   303                         filter = "(%s) and not (%s)" % (filter, conf.except_filter)
   304                     else:
   305                         filter = "not (%s)" % conf.except_filter
   306                 if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
   307                     if filter:
   308                         filter = "(ether proto %i) and (%s)" % (type,filter)
   309                     else:
   310                         filter = "ether proto %i" % type
   311             if filter:
   312                 self.ins.setfilter(filter)
   313             self.outs = dnet.eth(iface)
   314         def recv(self,x=MTU):
   315             ll = self.ins.datalink()
   316             if ll in conf.l2types:
   317                 cls = conf.l2types[ll]
   318             else:
   319                 cls = conf.default_l2
   320                 warning("Unable to guess datalink type (interface=%s linktype=%i). Using %s" % (self.iface, ll, cls.name))
   321     
   322             pkt = self.ins.next()
   323             if pkt is not None:
   324                 ts,pkt = pkt
   325             if pkt is None:
   326                 return
   327             
   328             try:
   329                 pkt = cls(pkt)
   330             except KeyboardInterrupt:
   331                 raise
   332             except:
   333                 if conf.debug_dissector:
   334                     raise
   335                 pkt = conf.raw_layer(pkt)
   336             pkt.time = ts
   337             return pkt
   338     
   339         def nonblock_recv(self):
   340             self.ins.setnonblock(1)
   341             p = self.recv(MTU)
   342             self.ins.setnonblock(0)
   343             return p
   344     
   345         def close(self):
   346             if hasattr(self, "ins"):
   347                 del(self.ins)
   348             if hasattr(self, "outs"):
   349                 del(self.outs)