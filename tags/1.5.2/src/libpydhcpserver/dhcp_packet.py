# -*- encoding: utf-8 -*-
"""
libpydhcpserver module: dhcp_packet

Purpose
=======
 Extended class to offer convenience functions and processing for DHCP packets.
 
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
 
 (C) Neil Tallim, 2010 <red.hamsterx@gmail.com>
 (C) Mathieu Ignacio, 2008 <mignacio@april.org>
"""
import operator
from struct import unpack
from struct import pack

from dhcp_constants import *
from type_hwmac import hwmac
from type_ipv4 import ipv4
from type_strlist import strlist
from type_rfc import *

class DHCPPacket(object):
    """
    Handles the construction, management, and export of DHCP packets.
    """
    _packet_data = None #: The core 240 bytes that make up a DHCP packet.
    _options_data = None #: Any additional options attached to this packet.
    _requested_options = None #: Any options explicitly requested by the client.
    
    def __init__(self, data=None):
        """
        Initializes a DHCP packet, using real data, if possible.
        
        @type data: str|None
        @param data: The raw packet from which this object should be instantiated or None if a
            blank packet should be created.
        """
        self._options_data = {}
        if not data: #Just create a blank packet and bail.
            self._packet_data = [0]*240
            self._packet_data[236:240] = MAGIC_COOKIE
            return
            
        #Transform all data to a list of bytes by unpacking it as C-chars.
        unpack_fmt = str(len(data)) + "c"
        self._packet_data = [ord(i) for i in unpack(unpack_fmt, data)]
        
        #Some servers or clients don't place the magic cookie immediately
        #after the end of the headers block, adding unnecessary padding.
        #It's necessary to find the magic cookie before proceding.
        position = 236
        end_position = len(self._packet_data)
        while not self._packet_data[position:position + 4] == MAGIC_COOKIE and position < end_position:
            position += 1
        position += 4 #Jump to the point immediately after the cookie.
        
        #Extract extended options from the payload.
        while position < end_position:
            if self._packet_data[position] == 0: #Pad option; skip byte.
                opt_first = position + 1
                position += 1
            elif self._packet_data[position] == 255: #End option; stop processing.
                break
            elif DHCP_OPTIONS_TYPES.has_key(self._packet_data[position]) and not self._packet_data[position] == 255:
                opt_len = self._packet_data[position + 1]
                opt_first = position + 1
                opt_id = self._packet_data[position]
                opt_val = self._packet_data[opt_first + 1:opt_len + opt_first + 1]
                self._options_data[DHCP_OPTIONS_REVERSE[opt_id]] = opt_val
                if opt_id == 55: #Handle requested options.
                    self._requested_options = tuple(set(
                     [int(i) for i in opt_val] + [1, 3, 6, 15, 51, 53, 54, 58, 59]
                    ))
                position += self._packet_data[opt_first] + 2
            else:
                opt_first = position + 1
                position += self._packet_data[opt_first] + 2
                
        #Cut the packet data down to 240 bytes.
        self._packet_data = self._packet_data[:236] + MAGIC_COOKIE
        
    def encodePacket(self):
        """
        Assembles all data into a single, C-char-packed struct.
        
        All options are arranged in order, per RFC2131 (details under 'router').
        
        @rtype: str
        @return: The encoded packet.
        """
        #Pull options out of the payload, excluding options not specifically
        #requested, assuming any specific requests were made.
        options = {}
        for key in self._options_data.keys():
            option_id = DHCP_OPTIONS[key]
            if self._requested_options is None or option_id in self._requested_options:
                option_value = self._options_data[key]
                
                options[option_id] = option = []
                
                while True:
                    if len(option_value) > 255:
                        option += [option_id, 255] + option_value[:255]
                        option_value = option_value[255:]
                    else:
                        option += [option_id, len(option_value)] + option_value
                        break
        #Order options by number and add them to the output data.
        ordered_options = []
        for (option_id, value) in sorted(options.iteritems()):
            ordered_options += value
            
        #Assemble data.
        packet = self._packet_data[:240] + ordered_options
        packet.append(255) #Add End option.
        
        #Encode packet.
        pack_fmt = str(len(packet)) + "c"
        packet = map(chr, packet)
        
        return pack(pack_fmt, *packet)
        
    def _setRfcOption(self, name, value, expected_type):
        """
        Handles the process of setting RFC options, digesting the object's
        contents if an object of the appropriate type is provided, or directly
        assigning the list otherwise.
        
        @type name: basestring
        @param name: The option's name.
        @type value: L{RFC}|list
        @param value: The value to be assigned.
        @type expected_type: L{RFC}
        @param expected_type: The type of special RFC object associated with
            the given option name.
        
        @rtype: bool
        @return: True if assignment succeeded.
        """
        if type(value) == expected_type:
            self._options_data[name] = value.getValue()
            return True
        else:
            self._options_data[name] = value
            return True
        return False
        
    def deleteOption(self, name):
        """
        Drops a value from the DHCP data-set.
        
        If the value is part of the DHCP core, it is set to zero. Otherwise, it
        is removed from the option-pool.
        
        @type name: basestring|int
        @param name: The option's name or numeric value.
        
        @rtype: bool
        @return: True if the deletion succeeded.
        """
        if DHCP_FIELDS.has_key(name):
            dhcp_field = DHCP_FIELDS[name]
            begin = dhcp_field[0]
            end = dhcp_field[0] + dhcp_field[1]
            self._packet_data[begin:end] = [0]*dhcp_field[1]
            return True
        else:
            if type(name) == int: #Translate int to string.
                name = DHCP_OPTIONS_REVERSE.get(name)
            if self._options_data.has_key(name):
                del self._options_data[name]
                return True
        return False
        
    def forceOption(self, option, value):
        """
        Bypasses validation checks and adds the option number to the
        request-list. Useful to force poorly designed clients to perform
        specific tasks.
        
        @type name: basestring|int
        @param name: The option's name or numeric value.
        @type value: list|tuple
        @param value: The bytes to assign to this option.
        
        @raise ValueError: The specified option does not exist.
        """
        name = id = None
        if type(option) == int: #Translate int to string.
            name = DHCP_OPTIONS_REVERSE.get(option)
            id = option
        else: #Translate string into int.
            id = DHCP_OPTIONS.get(option)
            name = option
            
        if name and id:
            if self._requested_options:
                self._requested_options += (option,)
            self._options_data[name] = list(value)
        else:
            raise ValueError("Unknown option: %(option)s" % {
             'option': option,
            })
            
    def getOption(self, name):
        """
        Retrieves the value of an option in the packet's data.
        
        @type name: basestring|int
        @param name: The option's name or numeric value.
        
        @rtype: list|None
        @return: The value of the specified option or None if it hasn't been
            set.
        """
        if DHCP_FIELDS.has_key(name):
            option_info = DHCP_FIELDS[name]
            return self._packet_data[option_info[0]:option_info[0] + option_info[1]]
        else:
            if type(name) == int: #Translate int to string.
                name = DHCP_OPTIONS_REVERSE.get(name)
            if self._options_data.has_key(name):
                return self._options_data[name]
        return None
        
    def isOption(self, name):
        """
        Indicates whether an option is currently set within the packet.
        
        @type name: basestring|int
        @param name: The option's name or numeric value.
        
        @rtype: bool
        @return: True if the option has been set.
        """
        if type(name) == int: #Translate int to string.
            self._options_data.has_key(DHCP_OPTIONS_REVERSE.get(name))
        return self._options_data.has_key(name) or DHCP_FIELDS.has_key(name)
        
    def setOption(self, name, value):
        """
        Validates and sets the value of a DHCP option associated with this
        packet.
        
        @type name: basestring|int
        @param name: The option's name or numeric value.
        @type value: list|tuple|L{RFC}
        @param value: The bytes to assign to this option or the special RFC
            object from which they are to be derived.
        
        @rtype: bool
        @return: True if the value was set successfully.
        
        @raise ValueError: The specified option does not exist.
        """
        if not isinstance(value, RFC):
            if not type(value) in (list, tuple):
                return False
            if [None for v in value if not type(v) == int or not 0 <= v <= 255]:
                return False
            value = list(value)
            
        #Basic checking: is the length of the value valid?
        if DHCP_FIELDS.has_key(name):
            dhcp_field = DHCP_FIELDS[name]
            if not len(value) == dhcp_field[1]:
                return False 
            begin = dhcp_field[0]
            end = dhcp_field[0] + dhcp_field[1]
            self._packet_data[begin:end] = value
            return True
        else:
            if type(name) == int:
                name = DHCP_OPTIONS_REVERSE.get(name)
            dhcp_field_type = DHCP_OPTIONS_TYPES.get(DHCP_OPTIONS.get(name))
            if not dhcp_field_type:
                return False
                
            #Process normal options.
            dhcp_field_specs = DHCP_FIELDS_SPECS[dhcp_field_type]
            if dhcp_field_specs:
                (fixed_length, minimum_length, multiple) = dhcp_field_specs
                length = len(value)
                if fixed_length == length or (minimum_length <= length and length % multiple == 0):
                    self._options_data[name] = value
                    return True
                return False
            else:
                #Process special RFC options.
                if dhcp_field_type == 'RFC2610_78':
                    return self._setRfcOption(name, value, rfc2610_78)
                elif dhcp_field_type == 'RFC2610_79':
                    return self._setRfcOption(name, value, rfc2610_79)
                elif dhcp_field_type == 'RFC3361_120':
                    return self._setRfcOption(name, value, rfc3361_120)
                elif dhcp_field_type == 'RFC3397_119':
                    return self._setRfcOption(name, value, rfc3397_119)
                elif dhcp_field_type == 'RFC4174_83':
                    return self._setRfcOption(name, value, rfc4174_83)
                elif dhcp_field_type == 'RFC4280_88':
                    return self._setRfcOption(name, value, rfc4280_88)
                elif dhcp_field_type == 'RFC5223_137':
                    return self._setRfcOption(name, value, rfc5223_137)
                elif dhcp_field_type == 'RFC5678_139':
                    return self._setRfcOption(name, value, rfc5678_139)
                elif dhcp_field_type == 'RFC5678_140':
                    return self._setRfcOption(name, value, rfc5678_140)
        raise ValueError("Unknown option: %(name)s" % {
         'name': name,
        })
        
    def isDHCPPacket(self):
        """
        Indicates whether this packet is a DHCP packet or not.
        
        @rtype: bool
        @return: True if this packet is a DHCP packet.
        """
        return self._packet_data[236:240] == MAGIC_COOKIE
        
    def isDHCPDeclinePacket(self):
        """
        Indicates whether this is a DECLINE packet.
        
        @rtype: bool
        @return: True if this is a DECLINE packet.
        """
        return self.getOption('dhcp_message_type')[0] == 4
        
    def isDHCPDiscoverPacket(self):
        """
        Indicates whether this is a DISCOVER packet.
        
        @rtype: bool
        @return: True if this is a DISCOVER packet.
        """
        return self.getOption('dhcp_message_type')[0] == 1
        
    def isDHCPInformPacket(self):
        """
        Indicates whether this is an INFORM packet.
        
        @rtype: bool
        @return: True if this is an INFORM packet.
        """
        return self.getOption('dhcp_message_type')[0] == 8
        
    def isDHCPLeaseQueryPacket(self):
        """
        Indicates whether this is a LEASEQUERY packet.
        
        @rtype: bool
        @return: True if this is a LEASEQUERY packet.
        """
        return self.getOption('dhcp_message_type')[0] == 10
        
    def isDHCPReleasePacket(self):
        """
        Indicates whether this is a RELEASE packet.
        
        @rtype: bool
        @return: True if this is a RELEASE packet.
        """
        return self.getOption('dhcp_message_type')[0] == 7
        
    def isDHCPRequestPacket(self):
        """
        Indicates whether this is a REQUEST packet.
        
        @rtype: bool
        @return: True if this is a REQUEST packet.
        """
        return self.getOption('dhcp_message_type')[0] == 3
        
    def _transformBase(self):
        """
        Sets and removes options from the DHCP packet to make it suitable for
        returning to the client.
        """
        self.setOption("op", [2])
        self.setOption("hlen", [6])
        
        self.deleteOption("client_identifier")
        self.deleteOption("maximum_message_size")
        self.deleteOption("parameter_request_list")
        self.deleteOption("request_ip_address")
        self.deleteOption("secs")
        self.deleteOption("subnet_selection")
        
    def transformToDHCPAckPacket(self):
        """
        Transforms a DHCP packet received from a client into an ACK
        packet to be returned to the client.
        """
        self._transformBase()
        self.setOption("dhcp_message_type", [5])
        
    def transformToDHCPLeaseActivePacket(self):
        """
        Transforms a DHCP packet received from a client into a LEASEACTIVE
        packet to be returned to the client.
        """
        self._transformBase()
        self.setOption("dhcp_message_type", [13])
        
        self.deleteOption("ciaddr")
        
        self.deleteOption("file")
        self.deleteOption("sname")
        
    def transformToDHCPLeaseUnknownPacket(self):
        """
        Transforms a DHCP packet received from a client into a LEASEUNKNOWN
        packet to be returned to the client.
        """
        self._transformBase()
        self.setOption("dhcp_message_type", [12])
        
        self.deleteOption("ciaddr")
        
        self.deleteOption("file")
        self.deleteOption("sname")
        
    def transformToDHCPOfferPacket(self):
        """
        Transforms a DHCP packet received from a client into an OFFER
        packet to be returned to the client.
        """
        self._transformBase()
        self.setOption("dhcp_message_type", [2])
        
        self.deleteOption("ciaddr")
        
    def transformToDHCPNackPacket(self):
        """
        Transforms a DHCP packet received from a client into a NAK
        packet to be returned to the client.
        """
        self._transformBase()
        self.setOption("dhcp_message_type", [6])
        
        self.deleteOption("ciaddr")
        self.deleteOption("siaddr")
        self.deleteOption("yiaddr")
        
        self.deleteOption("file")
        self.deleteOption("sname")
        
        self.deleteOption("ip_address_lease_time_option")
        
    def getHardwareAddress(self):
        """
        Extracts the client's MAC address from the DHCP packet.
        
        @rtype: str
        @return: The client's MAC address.
        """
        length = self.getOption("hlen")[0]
        full_hw = self.getOption("chaddr")
        if length and length < len(full_hw):
            return hwmac(full_hw[0:length]).str()
        return hwmac(full_hw).str()
        
    def getRequestedOptions(self):
        """
        Returns the options requested by the client from which this packet
        was sent.
        
        @rtype: tuple|None
        @return: The options requested by the client or None if option 55 was
            omitted.
        """
        return self._requested_options
        
    def isRequestedOption(self, name):
        """
        Indicates whether the specified option was requested by the client or
        the client omitted option 55, necessitating delivery of all values.
        
        @type name: basestring|int
        @param name: The name (or numeric value) of the DHCP option being
            tested.
        
        @rtype: bool
        @return: True if the option was requested by the client.
        """
        if self._requested_options is None:
            return True
            
        if not type(name) == int:
            return DHCP_OPTIONS.get(name) in self._requested_options
        return name in self._requested_options
        
    def __str__(self):
        """
        Renders this packet's data in human-readable form.
        
        @rtype: str
        @return: A human-readable summary of this packet.
        """
        output = ['#Header fields']
        op = self._packet_data[DHCP_FIELDS['op'][0]:DHCP_FIELDS['op'][0] + DHCP_FIELDS['op'][1]]
        output.append("op: %(type)s" % {
         'type': DHCP_FIELDS_NAME['op'][op[0]],
        })
        
        for opt in (
         'htype','hlen','hops','xid','secs','flags',
         'ciaddr','yiaddr','siaddr','giaddr','chaddr',
         'sname','file',
        ):
            begin = DHCP_FIELDS[opt][0]
            end = DHCP_FIELDS[opt][0] + DHCP_FIELDS[opt][1]
            data = self._packet_data[begin:end]
            result = None
            if DHCP_FIELDS_TYPES[opt] == "byte":
                result = str(data[0])
            elif DHCP_FIELDS_TYPES[opt] == "16-bits":
                result = str(data[0] * 256 + data[1])
            elif DHCP_FIELDS_TYPES[opt] == "32-bits":
                result = str(ipv4(data).int())
            elif DHCP_FIELDS_TYPES[opt] == "string":
                result = []
                for c in data:
                    if c:
                        result.append(chr(c))
                    else:
                        break
                result = ''.join(result)
            elif DHCP_FIELDS_TYPES[opt] == "ipv4":
                result = ipv4(data).str()
            elif DHCP_FIELDS_TYPES[opt] == "hwmac":
                result = []
                hexsym = ('0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',)
                for iterator in xrange(6):
                    result.append(str(hexsym[data[iterator] / 16] + hexsym[data[iterator] % 16]))
                result = ':'.join(result)
            output.append("%(opt)s: %(result)s" % {
             'opt': opt,
             'result': result,
            })
            
        output.append('')
        output.append("#Options fields")
        for opt in self._options_data.keys():
            data = self._options_data[opt]
            result = None
            optnum  = DHCP_OPTIONS[opt]
            if opt == 'dhcp_message_type':
                result = DHCP_FIELDS_NAMES['dhcp_message_type'][data[0]]
            elif DHCP_OPTIONS_TYPES[optnum] in ("byte", "byte+", "string"):
                result = str(data)
            elif DHCP_OPTIONS_TYPES[optnum] in ("char", "char+"):
                if optnum == 55: # parameter_request_list
                    requested_options = []
                    for d in data:
                        requested_options.append(DHCP_OPTIONS_REVERSE[int(d)])
                    result = ', '.join(requested_options)
                else:
                    result = []
                    for c in data:
                        if 32 <= c <= 126:
                            result.append(chr(c))
                        else:
                            result.append(str(c))
                    result = ', '.join(result)
            elif DHCP_OPTIONS_TYPES[optnum] in ("16-bits", "16-bits+"):
                result = []
                for i in xrange(0, len(data), 2):
                    result.append(str(data[i] * 256 + data[i + 1]))
                result = ', '.join(result)
            elif DHCP_OPTIONS_TYPES[optnum] in ("32-bits", "32-bits+"):
                result = []
                for i in xrange(0, len(data), 4):
                    result.append(str(ipv4(data[i:i+4]).int()))
                result = ', '.join(result)
            elif DHCP_OPTIONS_TYPES[optnum] in ("ipv4", "ipv4+", "ipv4*"):
                result = []
                for i in xrange(0, len(data), 4):
                    result.append(ipv4(data[i:i+4]).str())
                result = ', '.join(result)
            else:
                result = str(data)
            output.append("%(opt)s: %(result)s" % {
             'opt': opt,
             'result': result,
            })
        return '\n'.join(output)
        
