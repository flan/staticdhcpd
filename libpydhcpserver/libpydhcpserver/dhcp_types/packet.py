# -*- encoding: utf-8 -*-
"""
libpydhcpserver.dhcp_types.packet
=================================
Defines the structure of a DHCP packet, providing methods for manipulation.

Legal
-----
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

(C) Neil Tallim, 2013 <flan@uguu.ca>
(C) Mathieu Ignacio, 2008 <mignacio@april.org>
"""
from array import array

from constants import (
 MAGIC_COOKIE, MAGIC_COOKIE_ARRAY,
 DHCP_FIELDS_NAMES, DHCP_FIELDS, DHCP_FIELDS_SPECS, DHCP_FIELDS_TYPES,
 DHCP_OPTIONS_TYPES, DHCP_OPTIONS, DHCP_OPTIONS_REVERSE,
)
from mac import MAC
from ipv4 import IPv4
from rfc import (RFC, rfc3046_decode)
import conversion

_MAGIC_COOKIE_POSITION = 236
_PACKET_HEADER_SIZE = 240

_MANDATORY_OPTIONS = set((
 1, #subnet_mask
 3, #router
 6, #domain_name_servers
 15, #domain_name
 51, #ip_address_lease_time
 53, #dhcp_message_type
 54, #server_identifier
 58, #renewal_time_value
 59, #rebinding_time_value
)) #: All options to force a client to receive, even if not requested.

_OPTION_ORDERING = (
 DHCP_OPTIONS['dhcp_message_type'], #53
 DHCP_OPTIONS['server_identifier'], #54
 DHCP_OPTIONS['ip_address_lease_time'], #51
)

_FORMAT_CONVERSION_SERIAL = {
 'ipv4': conversion.ipToList,
 'ipv4+': conversion.ipsToList,
 'ipv4*': conversion.ipsToList,
 'byte': lambda b: [b],
 'byte+': list,
 'char': conversion.strToList,
 'char+': conversion.strToList,
 'string': conversion.strToList,
 'bool': int,
 '16-bits': conversion.intToList,
 '16-bits+': conversion.intsToList,
 '32-bits': conversion.longToList,
 '32-bits+': conversion.longsToList,
 'identifier': conversion.intsToList,
 'none': lambda v: [0],
}
_FORMAT_CONVERSION_DESERIAL = {
 'ipv4': conversion.listToIP,
 'ipv4+': conversion.listToIPs,
 'ipv4*': conversion.listToIPs,
 'byte': lambda l: l[0],
 'byte+': lambda l: l,
 'char': conversion.listToStr,
 'char+': conversion.listToStr,
 'string': conversion.listToStr,
 'bool': bool,
 '16-bits': conversion.listToInt,
 '16-bits+': conversion.listToInts,
 '32-bits': conversion.listToLong,
 '32-bits+': conversion.listToLongs,
 'identifier': conversion.listToInts,
 'none': lambda v: None,
}

class DHCPPacket(object):
    """
    Handles the construction, management, and export of DHCP packets.
    """
    _header = None #: The core 240 bytes that make up a DHCP packet.
    _options = None #: Any options attached to this packet.
    _requested_options = None #: Any options explicitly requested by the client.
    _maximum_size = None #: The maximum number of bytes permitted in the encoded packet.
    
    word_align = False #If set, every option with an odd length in bytes will be padded, to ensure 16-bit word-alignment
    word_size = 4 #The number of bytes in a word; 32-bit by network convention by default
    terminal_pad = False #If set, pad the packet to ``word_size``
    
    response_mac = None #If set to something coerceable into a MAC, the packet will be sent to this MAC, rather than its default
    response_ip = None #If set to something coerceable into an IPv4, the packet will be sent to this IP, rather than its default
    response_port = None #If set to an integer, the packet will be sent to this port, rather than its default
    response_source_port = None #If set to an integer, the packet will be reported as being sent from this port, rather than its default
    
    def __init__(self, data=None, _copy_data=None):
        """
        Initializes a DHCP packet, using real data, if possible.
        
        @type data: str|None
        @param data: The raw packet from which this object should be instantiated or None if a
            blank packet should be created.
        """
        if not data:
            if _copy_data:
                self._copy(_copy_data)
            else:
                self._initialise()
            return
            
        options_position = self._locateOptions(data)
        
        #Recast the data as an array of bytes
        packet = array('B', data)
        
        options = self._decodeOptions(packet, options_position)
        self._options = options
        
        #Extract configuration data
        requested_options = options.get(55) #parameter_request_list
        if requested_options:
            self._requested_options = _MANDATORY_OPTIONS.union(requested_options)
        maximum_size = options.get(57)
        if maximum_size:
            self._maximum_size = conversion.listToInt(maximum_size)
            
        #Cut the packet data down to just the header and keep that.
        self._header = packet[:_PACKET_HEADER_SIZE]
        if options_position != _PACKET_HEADER_SIZE: #Insert the cookie without padding.
            self._header[_MAGIC_COOKIE_POSITION:_PACKET_HEADER_SIZE] = MAGIC_COOKIE_ARRAY
            
    def _decodeOptions(self, packet, position):
        global DHCP_OPTIONS_TYPES
        
        options = {}
        #Extract extended options from the payload.
        while position < end_position:
            if packet[position] == 0: #Pad option: skip byte.
                position += 1
                continue
            
            if packet[position] == 255: #End option: stop processing
                break
                
            option_id = packet[position]
            option_length = packet[position + 1]
            position += 2 #Skip the pointer past the identifier and length
            if option_id in DHCP_OPTIONS_TYPES:
                value = packet[position:position + option_length].tolist()
                if option_id in options: #It's a multi-part option
                    options[option_id].extend(value)
                else:
                    options[option_id] = value
            #else: it's something unimplemented, so just ignore it
            position += option_length #Skip the pointer past the payload_size
        return options
        
    def _locateOptions(self, data):
        #Some servers or clients don't place the magic cookie immediately
        #after the end of the headers block, adding unnecessary padding.
        #It's necessary to find the magic cookie.
        position = data.find(MAGIC_COOKIE, _MAGIC_COOKIE_POSITION)
        if position == -1:
            raise ValueError("Data received does not represent a DHCP packet: Magic Cookie not found")
        return position + len(MAGIC_COOKIE)
        
    def _initialise(self):
        self._options = {}
        self._header = array('B', [0] * _PACKET_HEADER_SIZE)
        self._header[_MAGIC_COOKIE_POSITION:_PACKET_HEADER_SIZE] = MAGIC_COOKIE_ARRAY
        
    def _copy(self, data):
        ((packet, options, requested_options, maximum_size),
         (word_align, word_size, terminal_pad),
         (response_mac, response_ip, response_port, response_source_port),
        ) = data
        self._header = packet[:]
        self._options = options.copy()
        self._requested_options = requested_options.copy()
        self._maximum_size = maximum_size
        
        self.word_align = word_align
        self.word_size = word_size
        self.terminal_pad = terminal_pad
        
        self.response_mac = response_mac
        self.response_ip = response_ip
        self.response_port = response_port
        self.response_source_port = response_source_port
        
    def copy(self):
        return DHCPPacket(_copy_data=(
         (self._header, self._options, self._requested_options, self._maximum_size),
         (self.word_align, self.word_size, self.terminal_pad),
         (self.response_mac, self.response_ip, self.response_port, self.response_source_port),
        ))
        
    def encodePacket(self):
        """
        Assembles all data into a single, C-char-packed struct.
        
        All options are arranged in order, per RFC2131 (details under 'router').
        
        @rtype: str
        @return: The encoded packet.
        """
        #Set namespace references for speed
        global DHCP_OPTIONS
        global _OPTION_ORDERING
        
        #Pull options out of the payload, excluding options not specifically
        #requested, assuming any specific requests were made.
        options = {}
        for (option_id, option_value) in self._options.iteritems():
            if self._requested_options is None or option_id in self._requested_options:
                options[option_id] = option = []
                while True:
                    if len(option_value) > 255:
                        option += [option_id, 255] + option_value[:255]
                        option_value = option_value[255:]
                    else:
                        option += [option_id, len(option_value)] + option_value
                        break
                        
        #Determine the order for options to appear in the packet
        keys = set(options.keys())
        option_ordering = [i for i in _OPTION_ORDERING if i in keys] #Put specific options first
        option_ordering.extend(sorted(keys.difference(option_ordering))) #Then sort the rest
        
        size_limit = (self._maximum_size or 0xFFFF) - _PACKET_HEADER_SIZE - 1 - 100 #Leave one for the end and some for the protocol header
        #Write them to the packet's buffer
        ordered_options = []
        for option_id in option_ordering:
            value = options[option_id]
            if self.word_align:
                for i in xrange(len(value) % self._word_size):
                    value.append(0) #Add a pad
                    
            if size_limit - len(value) >= 0: #Ensure that there's still space
                ordered_options += value
            else: #No more room
                break
                
        #Assemble data.
        ordered_options.append(255) #Add End option
        if self.terminal_pad:
            for i in xrange(min(len(value) % self._word_size, size_limit)):
                ordered_options.append(0) #Add trailing pads
        packet = self._header[:]
        packet.extend(ordered_options)
        
        #Encode packet.
        return packet.tostring()
        
    def _getOptionName(self, option):
        if type(option) is int:
            return DHCP_OPTIONS_REVERSE.get(option)
        return option
        
    def _getOptionID(self, option):
        if type(option) is not int:
            return DHCP_OPTIONS.get(option)
        return option
        
    def deleteOption(self, option):
        """
        Drops a value from the DHCP data-set.
        
        If the value is part of the DHCP core, it is set to zero. Otherwise, it
        is removed from the option-pool.
        
        @type option: basestring|int
        @param option: The option's name or numeric value.
        
        @rtype: bool
        @return: True if the deletion succeeded.
        """
        if option in DHCP_FIELDS:
            (start, length) = DHCP_FIELDS[option]
            self._header[start:start + length] = array('B', [0] * length)
            return True
        else:
            id = self._getOptionID(option)
            if id in self._options:
                del self._options[id]
                return True
        return False
        
    def forceOption(self, option, value):
        """
        Bypasses validation checks and adds the option number to the
        request-list. Useful to force spec-non-compliant clients to perform
        specific tasks.
        
        @type option: basestring|int
        @param option: The option's name or numeric value.
        @type value: list|tuple
        @param value: The bytes to assign to this option.
        
        @raise ValueError: The specified option does not exist.
        """
        id = self._getOptionID(option)
        if self._requested_options:
            self._requested_options.add(id)
        self._options[id] = list(value)
        else:
            raise ValueError("Unknown option: %(option)s" % {
             'option': option,
            })
            
    def _unconvertOptionValue(self, option, value):
        if option == 82: #relay_agent
            return rfc3046_decode(value)
            
        type = DHCP_FIELDS_TYPES.get(option) or DHCP_OPTIONS_TYPES.get(self._getOptionID(option))
        if not type in _FORMAT_CONVERSION_DESERIAL:
            return None
        return _FORMAT_CONVERSION_DESERIAL[type](value)
        
    def getOption(self, option, convert=False):
        """
        Retrieves the value of an option in the packet's data.
        
        @type option: basestring|int
        @param option: The option's name or numeric value.
        
        @rtype: list|None
        @return: The value of the specified option or None if it hasn't been
            set.
        """
        if option in DHCP_FIELDS:
            (start, length) = DHCP_FIELDS[option]
            value = self._header[start:start + length].tolist()
            if convert:
                return self._unconvertOptionValue(option, value)
            return value
        else:
            id = self._getOptionID(option)
            if id in self._options:
                value = self._options[id]
                if convert:
                    return self._unconvertOptionValue(id, value)
                return value
        return None
        
    def isOption(self, option):
        """
        Indicates whether an option is currently set within the packet.
        
        @type option: basestring|int
        @param option: The option's name or numeric value.
        
        @rtype: bool
        @return: True if the option has been set.
        """
        return self._getOptionID(option) in self._options or option in DHCP_FIELDS
        
    def _convertOptionValue(self, option, value):
        type = DHCP_FIELDS_TYPES.get(option) or DHCP_OPTIONS_TYPES.get(self._getOptionID(option))
        if not type or not type in _FORMAT_CONVERSION_SERIAL:
            return None
        return _FORMAT_CONVERSION_SERIAL[type](value)
        
    def setOption(self, option, value, convert=False):
        """
        Validates and sets the value of a DHCP option associated with this
        packet.
        
        @type option: basestring|int
        @param option: The option's name or numeric value.
        @type value: list|tuple|L{RFC} -- does some coercion
        @param value: The bytes to assign to this option or the special RFC
            object from which they are to be derived.
        
        @rtype: bool
        @return: True if the value was set successfully.
        
        @raise ValueError: The specified option does not exist.
        """
        #Ensure the input is a list of bytes or convert as needed
        if not isinstance(value, list):
            if isinstance(value, (tuple, array)):
                value = list(value)
            elif isinstance(value, RFC):
                value = value.getValue()
            elif convert:
                value = self._convertOptionValue(option, value)
                if value is None:
                    return False
            else:
                return False
        if any(True for v in value if type(v) is not int or not 0 <= v <= 255):
            return False
            
        if option in DHCP_FIELDS:
            #Validate the length of the value
            (start, length) = DHCP_FIELDS[option]
            if not len(value) == length:
                return False
            #Set it
            self._header[start:start + length] = array('B', value)
            return True
        else:
            id = self._getOptionID(option)
            dhcp_field_type = DHCP_OPTIONS_TYPES.get(id)
            if not dhcp_field_type:
                return False
                
            dhcp_field_specs = DHCP_FIELDS_SPECS.get(dhcp_field_type)
            if dhcp_field_specs: #It's a normal option
                #Validate the length of the value
                (fixed_length, minimum_length, multiple) = dhcp_field_specs
                length = len(value)
                if not (fixed_length == length or (minimum_length <= length and length % multiple == 0)):
                    return False
                #Set it
                self._options[id] = value
                return True
            elif dhcp_field_type.startswith('RFC'): #It's an RFC option; assume the value is right
                self._options[id] = value
                return True
        raise ValueError("Unknown option: %(option)s" % {
         'option': option,
        })
        
    def _getDHCPMessageType(self):
        """
        Returns the DHCP message-type of this packet.
        
        @rtype: int
        @return: The DHCP message type of this packet or -1 if the
            message-type is undefined.
        """
        dhcp_message_type = self.getOption('dhcp_message_type')
        if dhcp_message_type is None:
            return -1
        return dhcp_message_type[0]

    def getDHCPMessageTypeName(self):
        """
        Returns the DHCP packet-type-name of this packet as a string.
        """
        return DHCP_FIELDS_NAMES['dhcp_message_type'].get(self._getDHCPMessageType(), 'UNKNOWN_UNKNOWN')
        
    def isDHCPAckPacket(self):
        """
        Indicates whether this is an ACK packet.
        
        @rtype: bool
        @return: True if this is an ACK packet.
        """
        return self._getDHCPMessageType() == 5

    def isDHCPDeclinePacket(self):
        """
        Indicates whether this is a DECLINE packet.
        
        @rtype: bool
        @return: True if this is a DECLINE packet.
        """
        return self._getDHCPMessageType() == 4
        
    def isDHCPDiscoverPacket(self):
        """
        Indicates whether this is a DISCOVER packet.
        
        @rtype: bool
        @return: True if this is a DISCOVER packet.
        """
        return self._getDHCPMessageType() == 1
        
    def isDHCPInformPacket(self):
        """
        Indicates whether this is an INFORM packet.
        
        @rtype: bool
        @return: True if this is an INFORM packet.
        """
        return self._getDHCPMessageType() == 8
        
    def isDHCPLeaseActivePacket(self):
        """
        Indicates whether this is a LEASEACTIVE packet.
        
        @rtype: bool
        @return: True if this is a LEASEACTIVE packet.
        """
        return self._getDHCPMessageType() == 13
        
    def isDHCPLeaseQueryPacket(self):
        """
        Indicates whether this is a LEASEQUERY packet.
        
        @rtype: bool
        @return: True if this is a LEASEQUERY packet.
        """
        return self._getDHCPMessageType() == 10
        
    def isDHCPLeaseUnassignedPacket(self):
        """
        Indicates whether this is a LEASEUNASSIGNED packet.
        
        @rtype: bool
        @return: True if this is a LEASEUNASSIGNED packet.
        """
        return self._getDHCPMessageType() == 11
        
    def isDHCPLeaseUnknownPacket(self):
        """
        Indicates whether this is a LEASEUNKNOWN packet.
        
        @rtype: bool
        @return: True if this is a LEASEUNKNOWN packet.
        """
        return self._getDHCPMessageType() == 12
        
    def isDHCPOfferPacket(self):
        """
        Indicates whether this is an OFFER packet.
        
        @rtype: bool
        @return: True if this is an OFFER packet.
        """
        return self._getDHCPMessageType() == 2
        
    def isDHCPNakPacket(self):
        """
        Indicates whether this is a NAK packet.
        
        @rtype: bool
        @return: True if this is a NAK packet.
        """
        return self._getDHCPMessageType() == 6
        
    def isDHCPReleasePacket(self):
        """
        Indicates whether this is a RELEASE packet.
        
        @rtype: bool
        @return: True if this is a RELEASE packet.
        """
        return self._getDHCPMessageType() == 7
        
    def isDHCPRequestPacket(self):
        """
        Indicates whether this is a REQUEST packet.
        
        @rtype: bool
        @return: True if this is a REQUEST packet.
        """
        return self._getDHCPMessageType() == 3
        
    def extractIPOrNone(self, parameter):
        """
        Extracts the identified packet-field-IP and returns it if it is defined,
        None otherwise.
        """
        addr = self.getOption(parameter)
        if not addr or not any(addr):
            return None
        return IPv4(addr)
        
    def extractPXEOptions(self):
        """
        Strips out PXE-specific options from the packet, returning them
        separately.
        
        This function is good for scrubbing information that needs to be sent
        monodirectionally from the client.

        @rtype: tuple(3)
        @return: A triple containing, in order, option 93 (client_system) as
            a sequence of ints, option 94 (client_ndi) as a sequence of three
            bytes, and option 97 (uuid_guid) as digested data:
            (type:byte, data:[byte]).
            Any unset options are presented as None.
        """
        option_93 = self.getOption("client_system")
        option_94 = self.getOption("client_ndi")
        option_97 = self.getOption("uuid_guid")

        if option_93:
            value = []
            for i in xrange(0, len(option_93), 2):
                value.append(option_93[i] * 256 + option_93[i + 1])
            option_93 = value
            
        if option_94:
            option_94 = tuple(option_94)
            
        if option_97:
            option_97 = (option_97[0], option_97[1:])
            
        self.deleteOption("client_system")
        self.deleteOption("client_ndi")
        self.deleteOption("uuid_guid")
        
        return (option_93, option_94, option_97)
        
    def extractVendorOptions(self):
        """
        Strips out vendor-specific options from the packet, returning them
        separately.
        
        This function is good for scrubbing information that needs to be sent
        monodirectionally from the client.

        @rtype: tuple(4)
        @return: A four-tuple containing, in order, option 43
            (vendor_specific_information) as a string of bytes, option 60
            (vendor_class_identifier) as a string, and both option 124
            (vendor_class) and option 125 (vendor_specific) as digested data:
            [(enterprise_number:int, data:string)] and
            [(enterprise_number:int, [(suboption_code:byte, data:string)])],
            respectively. Any unset options are presented as None.
        """
        option_43 = self.getOption("vendor_specific_information")
        option_60 = self.getOption("vendor_class_identifier")
        option_124 = self.getOption("vendor_class")
        option_125 = self.getOption("vendor_specific")
        
        if option_124:
            data = []
            while option_124:
                enterprise_number = int(IPv4(option_124[:4]))
                option_124 = option_124[4:]
                payload_size = option_124[0]
                payload = option_124[1:1 + payload_size]
                option_124 = option_124[1 + payload_size:]
                
                data.append((enterprise_number, payload))
            option_124 = data
            
        if option_125:
            data = []
            while option_125:
                enterprise_number = int(IPv4(option_125[:4]))
                option_125 = option_125[4:]
                payload_size = option_125[0]
                payload = option_125[1:1 + payload_size]
                option_125 = option_125[1 + payload_size:]
                
                subdata = []
                while payload:
                    subopt = payload[0]
                    suboption_size = payload[1]
                    subpayload = payload[2:2 + suboption_size]
                    payload = payload[2 + suboption_size:]
                    subdata.append((subopt, subpayload))
                    
                data.append((enterprise_number, subdata))
            option_125 = data
            
        self.deleteOption("vendor_specific_information")
        self.deleteOption("vendor_class_identifier")
        self.deleteOption("vendor_class")
        self.deleteOption("vendor_specific")
        
        return (option_43, option_60, option_124, option_125)
        
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
        
    def transformToDHCPLeaseUnassignedPacket(self):
        """
        Transforms a DHCP packet received from a client into a LEASEUNASSIGNED
        packet to be returned to the client.
        """
        self._transformBase()
        self.setOption("dhcp_message_type", [11])
        
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
        
    def transformToDHCPNakPacket(self):
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
        Extracts the client's MAC address from the DHCP packet, as a
        `types.mac.MAC` object.
        """
        length = self.getOption("hlen")[0]
        full_hw = self.getOption("chaddr")
        if length and length < len(full_hw):
            return MAC(full_hw[0:length])
        return MAC(full_hw)
        
    def setHardwareAddress(self, mac):
        """
        Sets the client's MAC address in the DHCP packet, using a
        `types.mac.MAC` object.
        """
        full_hw = self.getOption("chaddr")
        mac = list(mac)
        mac.extend([0] * (len(full_hw) - len(mac)))
        self.setOption("chaddr", mac)
        
    def getRequestedOptions(self):
        """
        Returns the options requested by the client from which this packet
        was sent.
        
        @rtype: tuple|None
        @return: The options requested by the client or None if option 55 was
            omitted.
        """
        return tuple(sorted(self._requested_options))
        
    def isRequestedOption(self, option):
        """
        Indicates whether the specified option was requested by the client or
        the client omitted option 55, necessitating delivery of all values.
        
        @type option: basestring|int
        @param option: The name (or numeric value) of the DHCP option being
            tested.
        
        @rtype: bool
        @return: True if the option was requested by the client.
        """
        if self._requested_options is None:
            return True
            
        id = self._getOptionID(option)
        return id in self._requested_options
        
    def __str__(self):
        """
        Renders this packet's data in human-readable form.
        
        @rtype: str
        @return: This packet's contents, in human-readable form.
        """
        global _FORMAT_CONVERSION_DESERIAL
        
        output = ['Header:']
        (start, length) = DHCP_FIELDS['op']
        op = self._header[start:start + length]
        output.append("\top: %(type)s" % {
         'type': DHCP_FIELDS_NAMES['op'][op[0]],
        })
        
        for field in DHCP_FIELDS.iterkeys():
            (start, length) = DHCP_FIELDS[field]
            data = self._header[start:start + length]
            field.append("\t%(field)s: %(result)r" % {
             'field': field,
             'result': _FORMAT_CONVERSION_DESERIAL[DHCP_FIELDS_TYPES[field]](data),
            })
            
        output.append('')
        output.append("Body:")
        for (option_id, data) in self._options.iteritems():
            result = None
            represent = False
            if option_id == 53: #dhcp_message_type
                result = self.getDHCPMessageTypeName()
            elif option_id == 55: #parameter_request_list
                requested_options = []
                for d in sorted(data):
                    requested_options.append("%(name)s (%(id)i)" % {
                     'name': DHCP_OPTIONS_REVERSE[d],
                     'id': d,
                    })
                result = ', '.join(requested_options)
            else:
                represent = True
                result = _FORMAT_CONVERSION_DESERIAL[DHCP_OPTIONS_TYPES[option_id]](data)
            output.append((represent and "\t[%(id)03i] %(name)s: %(result)r" or "\t[%(id)03i] %(name)s: %(result)s") % {
             'id': option_id,
             'name': self._getOptionName(option_id),
             'result': result,
            })
        return '\n'.join(output)
        