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
import collections

import constants
from constants import (
 FIELD_OP,
 FIELD_HTYPE, FIELD_HLEN, FIELD_HOPS,
 FIELD_XID, FIELD_SECS, FIELD_FLAGS,
 FIELD_CIADDR, FIELD_YIADDR, FIELD_SIADDR, FIELD_GIADDR,
 FIELD_CHADDR,
 FIELD_SNAME, FIELD_FILE,
 MAGIC_COOKIE, MAGIC_COOKIE_ARRAY,
 DHCP_OP_NAMES, DHCP_TYPE_NAMES,
 DHCP_FIELDS, DHCP_FIELDS_SPECS, DHCP_FIELDS_TYPES,
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
 constants.TYPE_IPV4: conversion.ipToList,
 constants.TYPE_IPV4_PLUS: conversion.ipsToList,
 constants.TYPE_IPV4_MULT: conversion.ipsToList,
 constants.TYPE_BYTE: lambda b: [b],
 constants.TYPE_BYTE_PLUS: list,
 constants.TYPE_STRING: conversion.strToList,
 constants.TYPE_BOOL: int,
 constants.TYPE_INT: conversion.intToList,
 constants.TYPE_INT_PLUS: conversion.intsToList,
 constants.TYPE_LONG: conversion.longToList,
 constants.TYPE_LONG_PLUS: conversion.longsToList,
 constants.TYPE_IDENTIFIER: conversion.intsToList,
 constants.TYPE_NONE: lambda _: [],
}
_FORMAT_CONVERSION_DESERIAL = {
 constants.TYPE_IPV4: conversion.listToIP,
 constants.TYPE_IPV4_PLUS: conversion.listToIPs,
 constants.TYPE_IPV4_MULT: conversion.listToIPs,
 constants.TYPE_BYTE: lambda l: l[0],
 constants.TYPE_BYTE_PLUS: lambda l: l,
 constants.TYPE_STRING: conversion.listToStr,
 constants.TYPE_BOOL: bool,
 constants.TYPE_INT: conversion.listToInt,
 constants.TYPE_INT_PLUS: conversion.listToInts,
 constants.TYPE_LONG: conversion.listToLong,
 constants.TYPE_LONG_PLUS: conversion.listToLongs,
 constants.TYPE_IDENTIFIER: conversion.listToInts,
 constants.TYPE_NONE: lambda _: None,
}

PXEOptions = collections.namedtuple("PXEOptions", (
 'client_system', 'client_ndi', 'uuid_guid'
))
"""
Provides PXE options in an easy-to-interpret form.

* ``client_system``: `option 93`, as a tuple of ints
* ``client_ndi``: `option 94` as a tuple of three bytes
* ``uuid_guid``: `option 97` as a tuple with the type in the first slot as a
    byte and a tuple of bytes in the second slot
    
Any unset options will be ``None``.
"""

VendorOptions = collections.namedtuple("VendorOptions", (
 'vendor_specific_information', 'vendor_class_identifier', 'vendor_class', 'vendor_specific',
))
"""
Provides vendor options in an easy-to-interpret form.

* ``vendor_specific_information``: `option 43`, as a string of bytes
* ``vendor_class_identifier``: `option 60` as a string
* ``vendor_class``: `option 124` as a dictionary of data as strings keyed by
    enterprise numbers
* ``vendor_specific``: `option 125` as a dictionary of data keyed by enterprise
    number; the values are dictionaries that map suboption IDs to data as
    strings

Any unset options will be ``None``.
"""

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
        maximum_datagram_size = 22 in options and conversion.listToInt(options[22])
        maximum_dhcp_size = 57 in options and conversion.listToInt(options[57])
        if maximum_datagram_size and maximum_dhcp_size:
            self._maximum_size = min(maximum_datagram_size, maximum_dhcp_size)
        else:
            self._maximum_size = maximum_datagram_size or maximum_dhcp_size
            
        #Cut the packet data down to just the header and keep that.
        self._header = packet[:_PACKET_HEADER_SIZE]
        if options_position != _PACKET_HEADER_SIZE: #Insert the cookie without padding.
            self._header[_MAGIC_COOKIE_POSITION:_PACKET_HEADER_SIZE] = MAGIC_COOKIE_ARRAY
            
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
        
    def _locateOptions(self, data):
        #Some servers or clients don't place the magic cookie immediately
        #after the end of the headers block, adding unnecessary padding.
        #It's necessary to find the magic cookie.
        position = data.find(MAGIC_COOKIE, _MAGIC_COOKIE_POSITION)
        if position == -1:
            raise ValueError("Data received does not represent a DHCP packet: Magic Cookie not found")
        return position + len(MAGIC_COOKIE)
        
    def _decodeOptions(self, packet, position):
        global DHCP_OPTIONS_TYPES
        
        options = {}
        #Extract extended options from the payload.
        end_position = len(packet)
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
        
    def _convertOptionValue(self, option, value):
        type = DHCP_FIELDS_TYPES.get(option) or DHCP_OPTIONS_TYPES.get(self._getOptionID(option))
        if not type or not type in _FORMAT_CONVERSION_SERIAL:
            raise ValueError("Requested option does not have a type-mapping for conversion: %(option)r" % {
             'option': value,
            })
        return _FORMAT_CONVERSION_SERIAL[type](value)
        
    def _unconvertOptionValue(self, option, value):
        if option == 82: #relay_agent
            return rfc3046_decode(value)
            
        type = DHCP_FIELDS_TYPES.get(option) or DHCP_OPTIONS_TYPES.get(self._getOptionID(option))
        if not type in _FORMAT_CONVERSION_DESERIAL:
            raise ValueError("Requested option does not have a type-mapping for conversion: %(option)r" % {
             'option': value,
            })
        return _FORMAT_CONVERSION_DESERIAL[type](value)
        
    def _extractList(self, value, option=None):
        """
        option -> conversion enabled
        """
        if not isinstance(value, list):
            if isinstance(value, tuple):
                value = list(value)
            elif isinstance(value, array):
                value = value.tolist()
            elif isinstance(value, RFC):
                value = value.getValue()
            elif option:
                value = self._convertOptionValue(option, value)
            else:
                raise TypeError("Value supplied could not be realised as a list: %(value)r" % {
                 'value': value,
                })
        if any(True for v in value if type(v) is not int or not 0 <= v <= 255):
            raise TypeError("Value supplied is not a sequence of bytes: %(value)r" % {
             'value': value,
            })
        return value
        
    def getHardwareAddress(self):
        """
        Extracts the client's MAC address from the DHCP packet, as a
        `types.mac.MAC` object.
        """
        length = self.getOption(FIELD_HLEN)[0]
        full_hw = self.getOption(FIELD_CHADDR)
        if length and length < len(full_hw):
            return MAC(full_hw[0:length])
        return MAC(full_hw)
        
    def setHardwareAddress(self, mac):
        """
        Sets the client's MAC address in the DHCP packet, using a
        `types.mac.MAC` object or a sequence of bytes (this does not include strings).
        
        #Raises TypeError if mac is not a sequence of bytes.
        """
        full_hw = self.getOption(FIELD_CHADDR)
        mac = self._extractList(mac)
        mac.extend([0] * (len(full_hw) - len(mac)))
        self.setOption(FIELD_CHADDR, mac)
        
    def _getOptionID(self, option):
        if type(option) is not int:
            id = DHCP_OPTIONS.get(option)
        elif not 0 < option < 255:
            id = None
            
        if id is None:
            raise LookupError("Option %(option)r is unknown" % {
             'option': option,
            })
        return id
        
    def _getOptionName(self, option):
        if type(option) is int:
            name = DHCP_OPTIONS_REVERSE.get(option)
        elif not name in DHCP_OPTIONS:
            name = None
            
        if name is None:
            raise LookupError("Option %(option)r is unknown" % {
             'option': option,
            })
        return name
        
    def isOption(self, option):
        """
        Indicates whether an option is currently set within the packet.
        
        @type option: basestring|int
        @param option: The option's name or numeric value.
        
        @rtype: bool
        @return: True if the option has been set.
        """
        return self._getOptionID(option) in self._options or option in DHCP_FIELDS
        
    def deleteOption(self, option):
        """
        Drops a value from the DHCP data-set.
        
        If the value is part of the DHCP core, it is set to zero. Otherwise, it
        is removed from the option-pool.
        
        @type option: basestring|int
        @param option: The option's name or numeric value.
        
        LookupError on invalid option
        
        @rtype: bool
        @return: True if something was removed.
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
        
    def getOption(self, option, convert=False):
        """
        Retrieves the value of an option in the packet's data.
        
        @type option: basestring|int
        @param option: The option's name or numeric value.
        
        LookupError on invalid option
        
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
        
    def setOption(self, option, value, force=False):
        """
        Validates and sets the value of a DHCP option associated with this
        packet.
        
        @type option: basestring|int
        @param option: The option's name or numeric value.
        @type value: list|tuple|L{RFC} -- does some coercion
        @param value: The bytes to assign to this option or the special RFC
            object from which they are to be derived.
            
        LookupError on invalid option
        TypeError on invalid value
        ValueError on invalid length
        """
        value = self._extractList(value, option=option)
        
        if option in DHCP_FIELDS:
            (start, length) = DHCP_FIELDS[option]
            if not len(value) == length:
                raise ValueError("Expected a value of length %(length)i, not %(value-length)i: %(value)r" % {
                 'length': length,
                 'value-length': len(value),
                 'value': value,
                })
            self._header[start:start + length] = array('B', value)
        else:
            id = self._getOptionID(option)
            dhcp_field_type = DHCP_OPTIONS_TYPES[id]
            dhcp_field_specs = DHCP_FIELDS_SPECS.get(dhcp_field_type)
            if dhcp_field_specs: #It's a normal option
                if not force: #Validate the length of the value
                    (fixed_length, minimum_length, multiple) = dhcp_field_specs
                    length = len(value)
                    if fixed_length != length:
                        if length < minimum_length or length % multiple:
                            raise ValueError("Expected a value a multiple of length %(length)i, not %(value-length)i: %(value)r" % {
                             'length': minimum_length,
                             'value-length': length,
                             'value': value,
                            })
                    elif not fixed_length:
                        raise ValueError("Expected a value of length %(length)i, not %(value-length)i: %(value)r" % {
                         'length': fixed_length,
                         'value-length': length,
                         'value': value,
                        })
                self._options[id] = value
            elif dhcp_field_type.startswith('RFC'): #It's an RFC option
                #Assume the value is right
                self._options[id] = value
            else:
                raise ValueError("Unsupported option: %(option)s" % {
                 'option': option,
                })
                
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
            
        return self._getOptionID(option) in self._requested_options
        
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
        """
        option_93 = self.getOption(93) #client_system
        option_94 = self.getOption(94) #client_ndi
        option_97 = self.getOption(97) #uuid_guid
        
        if option_93:
            value = []
            for i in xrange(0, len(option_93), 2):
                value.append(option_93[i] * 256 + option_93[i + 1])
            option_93 = tuple(value)
            
        if option_94:
            option_94 = tuple(option_94)
            
        if option_97:
            option_97 = (option_97[0], option_97[1:])
            
        self.deleteOption(93)
        self.deleteOption(94)
        self.deleteOption(97)
        
        return PXEOptions(option_93, option_94, option_97)
        
    def _parseEnterpriseOption(self, option, identifier_size):
        data = {}
        while option:
            enterprise_number = conversion.listToNumber(option[:identifier_size])
            payload_size = option[identifier_size]
            payload = option[1 + identifier_size:1 + identifier_size + payload_size]
            option = option[1 + identifier_size + payload_size:]
            data[enterprise_number] = payload
        return data
        
    def extractVendorOptions(self):
        """
        Strips out vendor-specific options from the packet, returning them
        separately.
        
        This function is good for scrubbing information that needs to be sent
        monodirectionally from the client.
        """
        option_43 = self.getOption(43) #vendor_specific_information
        option_60 = self.getOption(60) #vendor_class_identifier
        option_124 = self.getOption(124) #vendor_class
        option_125 = self.getOption(125) #vendor_specific
        
        if option_124:
            option_124 = self._parseEnterpriseOption(option_124, 4)
            
        if option_125:
            option_125 = self._parseEnterpriseOption(option_125, 4)
            for i in option_125:
                option_125[i] = self._parseEnterpriseOption(option_125[i], 1)
                
        self.deleteOption(43)
        self.deleteOption(60)
        self.deleteOption(124)
        self.deleteOption(125)
        
        return VendorOptions(option_43, option_60, option_124, option_125)
        
    def _getDHCPMessageType(self):
        """
        Returns the DHCP message-type of this packet.
        
        @rtype: int
        @return: The DHCP message type of this packet or -1 if the
            message-type is undefined.
        """
        dhcp_message_type = self.getOption(53)
        if dhcp_message_type is None:
            return -1
        return dhcp_message_type[0]

    def getDHCPMessageTypeName(self):
        """
        Returns the DHCP packet-type-name of this packet as a string.
        """
        return DHCP_TYPE_NAMES.get(self._getDHCPMessageType(), 'UNKNOWN_UNKNOWN')
        
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
        
    def _transformBase(self):
        """
        Sets and removes options from the DHCP packet to make it suitable for
        returning to the client.
        """
        self.setOption(FIELD_OP, [2])
        self.setOption(FIELD_HLEN, [6])
        
        self.deleteOption(FIELD_SECS)
        
        self.deleteOption(22) #maximum_datagram_reassembly_size
        self.deleteOption(50) #requested_ip_address
        self.deleteOption(55) #parameter_request_list
        self.deleteOption(57) #maximum_dhcp_message_size
        self.deleteOption(61) #client_identifier
        self.deleteOption(118) #subnet_selection
        
    def transformToDHCPAckPacket(self):
        """
        Transforms a DHCP packet received from a client into an ACK
        packet to be returned to the client.
        """
        self._transformBase()
        self.setOption(53, [5]) #dhcp_message_type
        
    def transformToDHCPLeaseActivePacket(self):
        """
        Transforms a DHCP packet received from a client into a LEASEACTIVE
        packet to be returned to the client.
        """
        self._transformBase()
        self.setOption(53, [13]) #dhcp_message_type
        
        self.deleteOption(FIELD_CIADDR)
        
        self.deleteOption(FIELD_FILE)
        self.deleteOption(FIELD_SNAME)
        
    def transformToDHCPLeaseUnassignedPacket(self):
        """
        Transforms a DHCP packet received from a client into a LEASEUNASSIGNED
        packet to be returned to the client.
        """
        self._transformBase()
        self.setOption(53, [11]) #dhcp_message_type
        
        self.deleteOption(FIELD_CIADDR)
        
        self.deleteOption(FIELD_FILE)
        self.deleteOption(FIELD_SNAME)
        
    def transformToDHCPLeaseUnknownPacket(self):
        """
        Transforms a DHCP packet received from a client into a LEASEUNKNOWN
        packet to be returned to the client.
        """
        self._transformBase()
        self.setOption(53, [12]) #dhcp_message_type
        
        self.deleteOption(FIELD_CIADDR)
        
        self.deleteOption(FIELD_FILE)
        self.deleteOption(FIELD_SNAME)
        
    def transformToDHCPOfferPacket(self):
        """
        Transforms a DHCP packet received from a client into an OFFER
        packet to be returned to the client.
        """
        self._transformBase()
        self.setOption(53, [2]) #dhcp_message_type
        
        self.deleteOption(FIELD_CIADDR)
        
    def transformToDHCPNakPacket(self):
        """
        Transforms a DHCP packet received from a client into a NAK
        packet to be returned to the client.
        """
        self._transformBase()
        self.setOption(53, [6]) #dhcp_message_type
        
        self.deleteOption(FIELD_CIADDR)
        self.deleteOption(FIELD_SIADDR)
        self.deleteOption(FIELD_YIADDR)

        self.deleteOption(FIELD_FILE)
        self.deleteOption(FIELD_SNAME)
        
        self.deleteOption(51) #ip_address_lease_time
        
    def __str__(self):
        """
        Renders this packet's data in human-readable form.
        
        @rtype: str
        @return: This packet's contents, in human-readable form.
        """
        global _FORMAT_CONVERSION_DESERIAL
        
        output = ['::Header::']
        
        (start, length) = DHCP_FIELDS[FIELD_OP]
        op = self._header[start:start + length]
        output.append("\top: %(type)s" % {
         'type': DHCP_OP_NAMES[op[0]],
        })
        
        output.append("\thwmac: %(mac)r" % {
         'mac': self.getHardwareAddress(),
        })
        
        for field in (
         FIELD_FLAGS, FIELD_HOPS, onstants.FIELD_SECS,
         FIELD_XID,
         FIELD_SIADDR, FIELD_GIADDR, FIELD_CIADDR, FIELD_YIADDR,
         FIELD_SNAME, FIELD_FILE,
        ):
            (start, length) = DHCP_FIELDS[field]
            data = self._header[start:start + length]
            output.append("\t%(field)s: %(result)r" % {
             'field': field,
             'result': _FORMAT_CONVERSION_DESERIAL[DHCP_FIELDS_TYPES[field]](data),
            })
            
        output.append('')
        output.append("::Body::")
        for (option_id, data) in sorted(self._options.items()):
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
        
