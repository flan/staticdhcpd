# -*- encoding: utf-8 -*-
"""
types.packet
============
An encapsulation of a DHCP packet, allowing for easy access and manipulation.

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
import logging

from constants import (
 MAGIC_COOKIE,
 DHCP_FIELDS_NAMES, DHCP_FIELDS, DHCP_FIELDS_SPECS, DHCP_FIELDS_TYPES,
 DHCP_OPTIONS_TYPES, DHCP_OPTIONS, DHCP_OPTIONS_REVERSE,
)
from mac import MAC
from ipv4 import IPv4
from rfc import (RFC, rfc3046_decode)
import conversion

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

_logger = logging.getLogger('libpydhcpserver.types.packet')

class DHCPPacket(object):
    """
    Handles the construction, management, and export of DHCP packets.
    """
    _packet_data = None #: The core 240 bytes that make up a DHCP packet.
    _options_data = None #: Any additional options attached to this packet.
    _requested_options = None #: Any options explicitly requested by the client.
    _terminal_pad = False #: True if the request had a pad after the end option.
    
    word_align = False #If set, every option with an odd length in bytes will be padded, to ensure 16-bit word-alignment
    word_size = 4 #The number of bytes in a word; 32-bit by network convention by default
    terminal_pad = True #If set, if the client ended its request with a pad, one will be added in the response
    
    response_mac = None #If set to something coerceable into a MAC, the packet will be sent to this MAC, rather than its default
    response_ip = None #If set to something coerceable into an IPv4, the packet will be sent to this IP, rather than its default
    response_port = None #If set to an integer, the packet will be sent to this port, rather than its default
    response_source_port = None #If set to an integer, the packet will be reported as being sent from this port, rather than its default
    
    def __init__(self, data=None):
        """
        Initializes a DHCP packet, using real data, if possible.
        
        @type data: str|None
        @param data: The raw packet from which this object should be instantiated or None if a
            blank packet should be created.
        """
        if type(data) is tuple: #Duplicating an existing packet
            ((packet_data, options_data, requested_options),
             terminal_pad,
             (word_align, word_size),
             (response_mac, response_ip, response_port, response_source_port),
            ) = _copy_data
            self._packet_data = packet_data[:]
            self._options_data = options_data.copy()
            self._requested_options = requested_options[:]
            self._terminal_pad = self.terminal_pad = terminal_pad
            
            self.word_align = word_align
            self.word_size = word_size
            
            self.response_mac = response_mac
            self.response_ip = response_ip
            self.response_port = response_port
            self.response_source_port = response_source_port
            return
            
        self._options_data = {}
        if not data: #Just create a blank packet and bail.
            self._packet_data = array('B', [0] * 240)
            self._packet_data[236:240] = MAGIC_COOKIE
            return
            
        #Recast the data as an array of bytes
        packet_data = array('B', data)
        
        #Some servers or clients don't place the magic cookie immediately
        #after the end of the headers block, adding unnecessary padding.
        #It's necessary to find the magic cookie before proceding.
        position = 236
        end_position = len(packet_data)
        while not packet_data[position:position + 4] == MAGIC_COOKIE and position < end_position:
            position += 1
        if position == end_position:
            raise ValueError("Data received does not represent a DHCP packet: Magic Cookie not found")
        position += 4 #Jump to the point immediately after the cookie.
        
        #Extract extended options from the payload.
        while position < end_position:
            if packet_data[position] == 0: #Pad option; skip byte.
                opt_first = position + 1
                position += 1
            elif packet_data[position] == 255: #End option; stop processing
                if position + 1 < end_position: #But first, check to see if there was a trailing pad
                    self._terminal_pad = packet_data[position + 1] == 0
                break
            elif packet_data[position] in DHCP_OPTIONS_TYPES:
                opt_len = packet_data[position + 1]
                opt_first = position + 1
                opt_id = packet_data[position]
                opt_val = packet_data[opt_first + 1:opt_len + opt_first + 1].tolist()
                try:
                    self._options_data[DHCP_OPTIONS_REVERSE[opt_id]] = opt_val
                except Exception, e:
                    _logger.warn("Unable to assign '%(value)s' to '%(id)s': %(error)s" % {
                     'value': opt_val,
                     'id': opt_id,
                     'error': str(e),
                    })
                    
                if opt_id == 55: #Handle requested options.
                    self._requested_options = tuple(set(int(i) for i in opt_val).union((1, 3, 6, 15, 51, 53, 54, 58, 59)))
                position += packet_data[opt_first] + 2
            else:
                opt_first = position + 1
                position += packet_data[opt_first] + 2
                
        #Cut the packet data down to 240 bytes.
        self._packet_data = packet_data[:240]
        self._packet_data[236:240] = MAGIC_COOKIE
        
    def copy(self):
        return DHCPPacket(data=(
         (self._packet_data, self._options_data, self._requested_options),
         self.terminal_pad and self._terminal_pad,
         (self.word_align, self.word_size),
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
        for key in self._options_data:
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
                        
        #Determine the order for options to appear in the packet
        keys = set(options.keys())
        option_ordering = [i for i in _OPTION_ORDERING if i in keys] #Put specific options first
        option_ordering.extend(sorted(keys.difference(option_ordering))) #Then sort the rest
        
        #Write them to the packet's buffer
        ordered_options = []
        for option_id in option_ordering:
            value = options[option_id]
            ordered_options += value
            if self.word_align:
                for i in xrange((len(value) ^ 0b00) & 0b11): #Equivalent to % 4
                    ordered_options.append(0) #Add a pad
                    
        #Assemble data.
        ordered_options.append(255) #Add End option
        if self.terminal_pad and self._terminal_pad:
            ordered_options.append(0) #Add a trailing Pad option, since the client sent one this way
        packet = self._packet_data[:]
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
        if name in DHCP_FIELDS:
            (start, length) = DHCP_FIELDS[name]
            self._packet_data[start:start + length] = array('B', [0] * length)
            return True
        else:
            name = self._getOptionName(name)
            if name in self._options_data:
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
        name = self._getOptionName(option)
        id = self._getOptionID(option)
        if name and id:
            if self._requested_options:
                self._requested_options += (id,)
            self._options_data[name] = list(value)
        else:
            raise ValueError("Unknown option: %(option)s" % {
             'option': option,
            })
            
    def _unconvertOptionValue(self, name, value):
        if name == 'relay_agent': #Option 82
            return rfc3046_decode(value)
            
        type = DHCP_FIELDS_TYPES.get(name) or DHCP_OPTIONS_TYPES.get(name)
        if not type in _FORMAT_CONVERSION_DESERIAL:
            return None
        return _FORMAT_CONVERSION_DESERIAL[type](value)
        
    def getOption(self, name, convert=False):
        """
        Retrieves the value of an option in the packet's data.
        
        @type name: basestring|int
        @param name: The option's name or numeric value.
        
        @rtype: list|None
        @return: The value of the specified option or None if it hasn't been
            set.
        """
        if name in DHCP_FIELDS:
            (start, length) = DHCP_FIELDS[name]
            value = self._packet_data[start:start + length].tolist()
            if convert:
                return self._unconvertOptionValue(name, value)
            return value
        else:
            name = self._getOptionName(name)
            if name in self._options_data:
                value = self._options_data[name]
                if convert:
                    return self._unconvertOptionValue(name, value)
                return value
        return None
        
    def isOption(self, name):
        """
        Indicates whether an option is currently set within the packet.
        
        @type name: basestring|int
        @param name: The option's name or numeric value.
        
        @rtype: bool
        @return: True if the option has been set.
        """
        name = self._getOptionName(name)
        return name in self._options_data or name in DHCP_FIELDS
        
    def _convertOptionValue(self, name, value):
        type = DHCP_FIELDS_TYPES.get(name) or DHCP_OPTIONS_TYPES.get(name)
        if not type or not type in _FORMAT_CONVERSION_SERIAL:
            return None
        return _FORMAT_CONVERSION_SERIAL[type](value)
        
    def setOption(self, name, value, convert=False):
        """
        Validates and sets the value of a DHCP option associated with this
        packet.
        
        @type name: basestring|int
        @param name: The option's name or numeric value.
        @type value: list|tuple|L{RFC} -- does some coercion
        @param value: The bytes to assign to this option or the special RFC
            object from which they are to be derived.
        
        @rtype: bool
        @return: True if the value was set successfully.
        
        @raise ValueError: The specified option does not exist.
        """
        #Ensure the input is a list of bytes
        if not isinstance(value, list):
            if isinstance(value, (tuple, array)):
                value = list(value)
            elif convert:
                value = self._convertOptionValue(name, value)
                if value is None:
                    return False
            else:
                return False
        if any(True for v in value if type(v) is not int or not 0 <= v <= 255):
            return False
            
        #Basic checking: is the length of the value valid?
        if name in DHCP_FIELDS:
            (start, length) = DHCP_FIELDS[name]
            if not len(value) == length:
                return False 
            self._packet_data[start:start + length] = array('B', value)
            return True
        else:
            name = self._getOptionName(name)
            dhcp_field_type = DHCP_OPTIONS_TYPES.get(DHCP_OPTIONS.get(name))
            if not dhcp_field_type:
                return False
                
            dhcp_field_specs = DHCP_FIELDS_SPECS.get(dhcp_field_type)
            if dhcp_field_specs: #Process normal options.
                (fixed_length, minimum_length, multiple) = dhcp_field_specs
                length = len(value)
                if fixed_length == length or (minimum_length <= length and length % multiple == 0):
                    self._options_data[name] = value
                    return True
                return False
            elif dhcp_field_type.lower().startswith('rfc_'): #Process RFC options.
                if isinstance(value, RFC):
                    value = value.getValue()
                self._options_data[name] = value
                return True
        raise ValueError("Unknown option: %(name)s" % {
         'name': name,
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
        opt_93 = self.getOption("client_system")
        opt_94 = self.getOption("client_ndi")
        opt_97 = self.getOption("uuid_guid")

        if opt_93:
            value = []
            for i in xrange(0, len(opt_93), 2):
                value.append(opt_93[i] * 256 + opt_93[i + 1])
            opt_93 = value
            
        if opt_94:
            opt_94 = tuple(opt_94)
            
        if opt_97:
            opt_97 = (opt_97[0], opt_97[1:])
            
        self.deleteOption("client_system")
        self.deleteOption("client_ndi")
        self.deleteOption("uuid_guid")
        
        return (opt_93, opt_94, opt_97)
        
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
            [(enterprise_number:int, [(subopt_code:byte, data:string)])],
            respectively. Any unset options are presented as None.
        """
        opt_43 = self.getOption("vendor_specific_information")
        opt_60 = self.getOption("vendor_class_identifier")
        opt_124 = self.getOption("vendor_class")
        opt_125 = self.getOption("vendor_specific")
        
        if opt_124:
            data = []
            while opt_124:
                enterprise_number = int(IPv4(opt_124[:4]))
                opt_124 = opt_124[4:]
                payload_size = opt_124[0]
                payload = opt_124[1:1 + payload_size]
                opt_124 = opt_124[1 + payload_size:]
                
                data.append((enterprise_number, payload))
            opt_124 = data
            
        if opt_125:
            data = []
            while opt_125:
                enterprise_number = int(IPv4(opt_125[:4]))
                opt_125 = opt_125[4:]
                payload_size = opt_125[0]
                payload = opt_125[1:1 + payload_size]
                opt_125 = opt_125[1 + payload_size:]
                
                subdata = []
                while payload:
                    subopt = payload[0]
                    subopt_size = payload[1]
                    subpayload = payload[2:2 + subopt_size]
                    payload = payload[2 + subopt_size:]
                    subdata.append((subopt, subpayload))
                    
                data.append((enterprise_number, subdata))
            opt_125 = data
            
        self.deleteOption("vendor_specific_information")
        self.deleteOption("vendor_class_identifier")
        self.deleteOption("vendor_class")
        self.deleteOption("vendor_specific")
        
        return (opt_43, opt_60, opt_124, opt_125)
        
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
            
        id = self._getOptionName(name)
        return id in self._requested_options
        
    def __str__(self):
        """
        Renders this packet's data in human-readable form.
        
        @rtype: str
        @return: A human-readable summary of this packet.
        """
        global _FORMAT_CONVERSION_DESERIAL
        
        output = ['Header:']
        (start, length) = DHCP_FIELDS['op']
        op = self._packet_data[start:start + length]
        output.append("\top: %(type)s" % {
         'type': DHCP_FIELDS_NAMES['op'][op[0]],
        })
        
        for opt in DHCP_FIELDS.iterkeys():
            (start, length) = DHCP_FIELDS[opt]
            data = self._packet_data[start:start + length]
            output.append("\t%(opt)s: %(result)r" % {
             'opt': opt,
             'result': _FORMAT_CONVERSION_DESERIAL[DHCP_FIELDS_TYPES[opt]](data),
            })
            
        output.append('')
        output.append("Body:")
        for (opt, data) in self._options_data.iteritems():
            result = None
            represent = False
            optnum  = DHCP_OPTIONS[opt]
            if opt == 'dhcp_message_type':
                result = self.getDHCPMessageTypeName()
            elif opt == 'parameter_request_list':
                requested_options = []
                for d in data:
                    requested_options.append(DHCP_OPTIONS_REVERSE[int(d)])
                result = ', '.join(requested_options)
            else:
                represent = True
                result = _FORMAT_CONVERSION_DESERIAL[DHCP_OPTIONS_TYPES[opt]](data)
            output.append((represent and "\t[%(num)03i] %(opt)s: %(result)r" or "\t%(opt)s: %(result)s") % {
             'num': self._getOptionID(opt),
             'opt': opt,
             'result': result,
            })
        return '\n'.join(output)
        