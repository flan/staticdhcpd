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

(C) Neil Tallim, 2014 <flan@uguu.ca>
(C) Mathieu Ignacio, 2008 <mignacio@april.org>
"""
from array import array

from . import constants
from .constants import (
 FIELD_OP,
 FIELD_HTYPE, FIELD_HLEN, FIELD_HOPS,
 FIELD_XID, FIELD_SECS, FIELD_FLAGS,
 FIELD_CIADDR, FIELD_YIADDR, FIELD_SIADDR, FIELD_GIADDR,
 FIELD_CHADDR,
 FIELD_SNAME, FIELD_FILE,
 MAGIC_COOKIE, MAGIC_COOKIE_ARRAY,
 DHCP_OP_NAMES, DHCP_TYPE_NAMES,
 DHCP_FIELDS, DHCP_FIELDS_TEXT, DHCP_FIELDS_SPECS, DHCP_FIELDS_TYPES,
 DHCP_OPTIONS_TYPES, DHCP_OPTIONS, DHCP_OPTIONS_REVERSE,
)
from .mac import MAC
from .ipv4 import IPv4
from .rfc import (
 RFC,
 rfc3046_decode, rfc3925_decode, rfc3925_125_decode
)
from . import conversion

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
) #: The order in which clients usually expect to see key options.

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
} #: Seralising converters for DHCP types.
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
} #: Deserialising converters for DHCP types.
_OPTION_UNPACK = {
 82: rfc3046_decode, #relay_agent
 124: rfc3925_decode, #vendor_class
 125: rfc3925_125_decode, #vendor_specific
} #: Mappings for specific options that are decoded by default.

FLAGBIT_BROADCAST = 0b1000000000000000 #: The "broadcast bit", described in RFC 2131.

class DHCPPacket(object):
    """
    A malleable representation of a DHCP packet.
    """
    _header = None #: The core 240 bytes that make up a DHCP packet.
    _options = None #: Any options attached to this packet.
    _selected_options = None #: Any options explicitly requested by the client.
    _maximum_size = None #: The maximum number of bytes permitted in the encoded packet.
    _meta = None #: A dictionary that can be freely manipulated to store data for the lifetime of the packet; initialised on first request.
    
    word_align = False #: If set, every option with an odd length in bytes will be padded, to ensure 16-bit word-alignment.
    word_size = 4 #: The number of bytes in a word; 32-bit by network convention by default.
    terminal_pad = False #: If set, pad the packet to a multiple of ``word_size``.
    
    response_mac = None #: If set to something coerceable into a MAC, the packet will be sent to this MAC, rather than its default.
    response_ip = None #: If set to something coerceable into an IPv4, the packet will be sent to this IP, rather than its default.
    response_port = None #: If set to an integer, the packet will be sent to this port, rather than its default.
    response_source_port = None #: If set to an integer, the packet will be reported as being sent from this port, rather than its default.
    
    def __init__(self, data=None, _copy_data=None):
        """
        Initialises a DHCP packet.
        
        :param data: An optional byte-encoded DHCP packet, used to set initial
                     values.
        :param _copy_data: Pre-formatted data from a :class:`Packet <Packet>`,
                           used to quickly initialise a duplicate.
        :except ValueError: Invalid packet-data was provided.
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
        
        options = self._unpackOptions(packet, options_position)
        self._options = options
        
        #Extract configuration data
        requested_options = options.get(55) #parameter_request_list
        if requested_options:
            self._selected_options = _MANDATORY_OPTIONS.union(requested_options)
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
            
    @property
    def meta(self):
        """
        A dictionary that can be freely manipulated to store data for the
        lifetime of the packet.
        
        This data is not used by the packet in any way.
        """
        if self._meta is None: #Defer instantiation if not required
            self._meta = {}
        return self._meta
        
    def _initialise(self):
        """
        Creates a blank packet's structures.
        """
        self._options = {}
        self._header = array('B', [0] * _PACKET_HEADER_SIZE)
        self._header[_MAGIC_COOKIE_POSITION:_PACKET_HEADER_SIZE] = MAGIC_COOKIE_ARRAY
        
    def _copy(self, data):
        """
        Creates a copy of an existing packet.
        
        :param data: The data used to initialise this packet's data-structures.
        """
        ((packet, options, selected_options, maximum_size),
         (word_align, word_size, terminal_pad),
         (response_mac, response_ip, response_port, response_source_port),
         meta,
        ) = data
        self._header = packet[:]
        self._options = options.copy()
        self._selected_options = selected_options and selected_options.copy() or None
        self._maximum_size = maximum_size
        
        self.word_align = word_align
        self.word_size = word_size
        self.terminal_pad = terminal_pad
        
        self.response_mac = response_mac
        self.response_ip = response_ip
        self.response_port = response_port
        self.response_source_port = response_source_port
        
        if meta:
            self._meta = meta.copy()
            
    def copy(self):
        """
        Provides a mutable copy of a packet.
        
        :return: A copy of the packet.
        """
        return DHCPPacket(_copy_data=(
         (self._header, self._options, self._selected_options, self._maximum_size),
         (self.word_align, self.word_size, self.terminal_pad),
         (self.response_mac, self.response_ip, self.response_port, self.response_source_port),
         self._meta,
        ))
        
    def _locateOptions(self, data):
        """
        Provides the location at which DHCP options begin.
        
        :param str data: The raw byte-encoded packet.
        :return int: The position at which options begin.
        :except ValueError: No magic cookie present in the data.
        """
        #Some servers or clients don't place the magic cookie immediately
        #after the end of the headers block, adding unnecessary padding.
        #It's necessary to find the magic cookie.
        position = data.find(MAGIC_COOKIE, _MAGIC_COOKIE_POSITION)
        if position == -1:
            raise ValueError("Data received does not represent a DHCP packet: Magic Cookie not found")
        return position + len(MAGIC_COOKIE)
        
    def _unpackOptions(self, packet, position):
        """
        Extracts all of the options from the packet.
        
        :param array('B') packet: The packet's raw data.
        :param int position: The position at which option data begins.
        :return dict: A dictionary of byte-lists, keyed by option ID.
        """
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
        
    def _packOptions(self, options, option_ordering, size_limit):
        """
        Extracts all of the options from the packet.
        
        :param dict options: The option-data to be packed.
        :param list(int) option_ordering: The order in which to pack options.
        :param int size_limit: The number of bytes available to pack options.
        :return tuple(2): A list of packed option bytes and a list containing any
                       option-IDs that could not be packed.
        """
        ordered_options = []
        if size_limit <= 0:
            return (ordered_options, option_ordering[:])
            
        size_limit -= 1 #Leave space for the END byte.
        for (i, option_id) in enumerate(option_ordering):
            value = options[option_id]
            if self.word_align:
                for i in xrange(len(value) % self._word_size):
                    value.append(0) #Add a pad
                    
            if size_limit - len(value) >= 0: #Ensure that there's still space
                ordered_options += value
            else: #No more room
                break
        else:
            i = len(option_ordering)
        ordered_options.append(255) #Add End option
        return (ordered_options, option_ordering[i:])
        
    def encodePacket(self):
        """
        Assembles all data into a single, byte-encoded string.
        
        All options are arranged in order, per RFC2131 (details under 'router').
        
        :return str: The encoded packet.
        """
        #Pull options out of the payload, excluding options not specifically
        #requested, assuming any specific requests were made.
        options = {}
        for (option_id, option_value) in self._options.items():
            if self.isSelectedOption(option_id):
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
        
        #Prepare the main payload
        size_limit = (self._maximum_size or 0xFFFF) - _PACKET_HEADER_SIZE - 68 - 3 #Leave some for the protocol header and three for option 52, if needed
        (payload, option_ordering) = self._packOptions(options, option_ordering, size_limit)
        
        #Assemble data.
        payload.extend((0, 0, 0)) #Space for option 52
        if self.terminal_pad:
            terminal_pad_size = min(len(value) % self._word_size, size_limit)
            payload.extend(0 for i in xrange(terminal_pad_size)) #Add trailing pads
        else:
            terminal_pad_size = 0
            
        #Create the byte-array based on the current header for efficiency
        packet = self._header[:]
        #Resize it only once
        packet.extend(payload)
        
        #If there is remaining data, pack it using option 52, if possible.
        option_52 = 0
        for (field, option_52_value) in ((FIELD_SNAME, 2), (FIELD_FILE, 1)):
            if not option_ordering: #There are no more options to allocate
                break
            if any(i for i in self.getOption(field) if i != '\0'): #The field is occupied
                continue
                
            option_52 += option_52_value
            (location, size) = DHCP_FIELDS[field]
            (payload, option_ordering) = self._packOptions(options, option_ordering, size)
            packet[location:location + len(payload)] = array('B', payload)
            
        #Set option 52 in the packet if it's required.
        if option_52:
            packet[-(4 + terminal_pad_size)] = 52 #Option ID (takes the place of former END)
            packet[-(3 + terminal_pad_size)] = 1 #Option length
            packet[-(2 + terminal_pad_size)] = option_52 #Option value
            packet[-(1 + terminal_pad_size)] = 255 #END
            
        #Encode packet.
        return packet.tostring()
        
    def _serialiseOptionValue(self, option, value):
        """
        Serialises a DHCP option's value.
        
        :param option: The option's ID, either an integer or a string.
        :param value: The option's value.
        :return list(int): The serialised value.
        :except ValueError: Serialisation failed.
        """
        type = DHCP_FIELDS_TYPES.get(option) or DHCP_OPTIONS_TYPES.get(self._getOptionID(option))
        if not type or not type in _FORMAT_CONVERSION_SERIAL:
            raise ValueError("Requested option does not have a type-mapping for conversion: %(option)r" % {
             'option': value,
            })
        return _FORMAT_CONVERSION_SERIAL[type](value)
        
    def _deserialiseOptionValue(self, option, value):
        """
        Deserialises a DHCP option's value.
        
        :param option: The option's ID, either an integer or a string.
        :param list(int) value: The option's value.
        :return: The deserialised value.
        :except ValueError: Deserialisation failed.
        """
        decode = _OPTION_UNPACK.get(option)
        if decode:
            return decode(value)
            
        type = DHCP_FIELDS_TYPES.get(option) or DHCP_OPTIONS_TYPES.get(self._getOptionID(option))
        if not type in _FORMAT_CONVERSION_DESERIAL:
            raise ValueError("Requested option does not have a type-mapping for conversion: %(option)r" % {
             'option': value,
            })
        return _FORMAT_CONVERSION_DESERIAL[type](value)
        
    def _validateByteList(self, value):
        """
        Ensures that a sequence is comprised entirely of bytes.
        
        :param collection value: The sequence to be tested.
        :return bool: True if the sequence is comprised entirely of bytes.
        """
        return not any(True for v in value if type(v) is not int or not 0 <= v <= 255)
        
    def _extractList(self, value, option=None):
        """
        Ensures that the data being processed is expressed as a list of bytes.
        
        :param value: The data to be processed.
        :param option: The option-ID (int or string) for which the value is
                       being prepared, or None if it is unassociated.
        :return list(int): The data as a list of bytes.
        :except Exception: The data could not be converted.
        """
        original_value = value
        #If it's another type of sequence, convert it
        if isinstance(value, tuple):
            value = list(value)
        elif isinstance(value, array):
            value = value.tolist()
            
        #If it isn't already a list of bytes, process it
        if not isinstance(value, list) or not self._validateByteList(value):
            if isinstance(value, RFC):
                return value.getValue()
            #Resolve option-IDs only after all other possibilities, since other
            #wrappers do the right thing and need no help.
            if option:
                return self._serialiseOptionValue(option, value)
                
            raise TypeError("Value supplied cannot be converted into a list of bytes: %(value)r" % {
             'value': original_value,
            })
        return value
        
    def getHardwareAddress(self):
        """
        Provides the client's MAC address.
        
        :return: The client's MAC address.
        """
        length = self.getOption(FIELD_HLEN)[0]
        full_hw = self.getOption(FIELD_CHADDR)
        if length and length < len(full_hw):
            return MAC(full_hw[0:length])
        return MAC(full_hw)
        
    def setHardwareAddress(self, mac):
        """
        Sets the client's MAC address.
        
        :param mac: The MAC to be assigned.
        :except Exception: Proivded MAC could not be processed.
        """
        full_hw = self.getOption(FIELD_CHADDR)
        mac = self._extractList(mac)
        mac.extend([0] * (len(full_hw) - len(mac)))
        self.setOption(FIELD_CHADDR, mac)
        
    def _getFlags(self):
        """
        Retrieves the flags bitmap.
        
        :return int: A sixteen-bit bitmap of option-flags set on the packet.
        """
        flags = self.getOption('flags')
        return (flags[0] << 8) + flags[1]
        
    def _setFlags(self, flags):
        """
        Assigns the flags bitmap.
        
        :param int flags: A sixteen-bit bitmap of option-flags to set.
        """
        self.setOption('flags', [flags >> 8 & 0xFF, flags & 0xFF])
        
    def getFlag(self, bitflag):
        """
        Retrieves a flag-bit from the header.
        
        :param int bitflag: One of the flag-constants defined in this module,
                            like ``FLAGBIT_BROADCAST``.
        :return bool: The state of the bit.
        """
        return bool(self._getFlags() & bitflag)
        
    def setFlag(self, bitflag, state):
        """
        Modifies the header to set a flag-bit.
        
        :param int bitflag: One of the flag-constants defined in this module,
                            like ``FLAGBIT_BROADCAST``.
        :param bool state: Whether the bit should be set or not.
        :return tuple(2): Whether the bit was changed and its initial value,
                          expressed in boolean.
        """
        flags = self._getFlags()
        bit = bool(flags & bitflag)
        if bit != state:
            if state:
                flags |= bitflag
            else:
                flags &= ~bitflag
            self._setFlags(flags)
            return (True, bit)
        return (False, bit)
        
    def _getOptionID(self, option):
        """
        Resolves the numeric ID of an option.
        
        :param option: The numeric ID or name of an option.
        :return int: The option's ID.
        :except LookupError: The option is unknown or invalid.
        """
        if type(option) is not int:
            id = DHCP_OPTIONS.get(option)
        elif not 0 < option < 255: #Out of range.
            id = None
        else:
            id = option
            
        if id is None:
            raise LookupError("Option %(option)r is unknown" % {
             'option': option,
            })
        return id
        s
    def _getOptionName(self, option):
        """
        Resolves the name of an option.
        
        :param option: The numeric ID or name of an option.
        :return str: The option's name.
        :except LookupError: The option is unknown or invalid.
        """
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
        
        :param option: The numeric ID or name of the option to check.
        :return bool: True if the option has been set.
        """
        return self._getOptionID(option) in self._options or option in DHCP_FIELDS
        
    def deleteOption(self, option):
        """
        Drops a value from the packet.
        
        If the value is part of the DHCP core, it is set to zero. Otherwise, it
        is removed from the option-pool.
        
        :param option: The numeric ID or name of the option to remove.
        :return bool: True if something was removed.
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
        Retrieves the value of a field or option from the packet.
        
        :param option: The numeric ID or name of the option to retrieve.
        :param bool convert: Whether the option's value should be deserialised.
        :return: The option's value or None, if it has not been set.
        """
        if option in DHCP_FIELDS:
            (start, length) = DHCP_FIELDS[option]
            value = self._header[start:start + length].tolist()
            if convert:
                return self._deserialiseOptionValue(option, value)
            return value
        else:
            id = self._getOptionID(option)
            if id in self._options:
                value = self._options[id]
                if convert:
                    return self._deserialiseOptionValue(id, value)
                return value
        return None
        
    def setOption(self, option, value, validate=True, force_selection=False):
        """
        Validates and sets a field or option on the packet.
        
        :param option: The numeric ID or name of the option to set.
        :param value: The value to be assigned.
        :param bool validate: Whether validation tests should be performed.
        :param bool force_selection: Whether the option should be included in
                                     the serialised packet, even if option 55
                                     was provided and it was not explicitly
                                     requested.
        :except ValueError: Validation failed.
        :except LookupError: Option not recognised.
        :except TypeError: Value could not be serialised.
        """
        value = self._extractList(value, option=option)
        
        if option in DHCP_FIELDS:
            (start, length) = DHCP_FIELDS[option]
            padding = None
            if len(value) < length and option in DHCP_FIELDS_TEXT:
                padding = (0 for i in xrange(length - len(value)))
            elif not len(value) == length:
                raise ValueError("Expected a value of length %(length)i, not %(value-length)i: %(value)r" % {
                 'length': length,
                 'value-length': len(value),
                 'value': value,
                })
            replacement = array('B', value)
            if padding:
                replacement.extend(padding)
            self._header[start:start + length] = replacement
        else:
            id = self._getOptionID(option)
            dhcp_field_type = DHCP_OPTIONS_TYPES[id]
            dhcp_field_specs = DHCP_FIELDS_SPECS.get(dhcp_field_type)
            if dhcp_field_specs: #It's a normal option
                if validate: #Validate the length of the value
                    (fixed_length, minimum_length, multiple) = dhcp_field_specs
                    length = len(value)
                    if fixed_length != length:
                        if length < minimum_length or length % multiple:
                            raise ValueError("Expected a value a multiple of length %(length)i, not %(value-length)i: %(value)r" % {
                             'length': minimum_length,
                             'value-length': length,
                             'value': value,
                            })
                    elif minimum_length and not fixed_length:
                        raise ValueError("Expected a value of length %(length)i, not %(value-length)i: %(value)r" % {
                         'length': fixed_length,
                         'value-length': length,
                         'value': value,
                        })
            elif dhcp_field_type.startswith('RFC'): #It's an RFC option
                #Assume the value is right
                pass
            else:
                raise LookupError("Unsupported option: %(option)s" % {
                 'option': option,
                })
                
            self._options[id] = value
            if force_selection and self._selected_options is not None:
                self._selected_options.add(id)
                
    def getSelectedOptions(self, translate=False):
        """
        Returns all options marked for serialisation.
        
        :param bool translate: If ``True``, the returned items will be names,
                               not integers.
        :return tuple: All options slated to be included when serialised.
        """
        if self._selected_options:
            options = self._selected_options.intersection(self._options)
        else:
            options = self._options
            
        if translate:
            global DHCP_OPTIONS_REVERSE
            options = (DHCP_OPTIONS_REVERSE[option] for option in options)
            
        return tuple(sorted(options))
        
    def setSelectedOptions(self, added=None, removed=None):
        """
        Changes the set of selected options.
        
        This does not affect option-data currently defined, just what will be
        serialised.
        
        If both ``added`` and ``removed`` are ``None``, all options will be
        selected.
        
        If the all-selected state is active, setting either parameter will
        begin with an empty set.
        
        ``added`` is applied before ``removed``.
        
        :param collection added: The numeric IDs or names of options to add.
        :param collection removed: The numeric IDs or names of options to
                                   remove.
        """
        if added is None and removed is None:
            self._selected_options = None
        else:
            if self._selected_options is None:
                self._selected_options = set()
            if added:
                self._selected_options.update(i for i in (self._getOptionID(option) for option in added) if i is not None)
            if removed:
                self._selected_options.difference_update(i for i in (self._getOptionID(option) for option in removed) if i is not None)
                
    def isSelectedOption(self, option):
        """
        Indicates whether the specified option is slated for serialisation.
        
        :param option: The numeric ID or name of the option to check.
        :return bool: True if the option is slated for serialisation.
        """
        id = self._getOptionID(option)
        if not id in self._options:
            return False
            
        if self._selected_options is not None:
            return id in self._selected_options
        return True
        
    def extractIPOrNone(self, option):
        """
        Provides the IP associated with a DHCP field or option.
        
        :param option: The numeric ID or name of the option to check.
        
        :return: The associated address or None, if undefined.
        """
        addr = self.getOption(option)
        if not addr or not any(addr):
            return None
        return IPv4(addr)
        
    def _getDHCPMessageType(self):
        """
        Provides the DHCP message-type of this packet.
        
        :return int: The DHCP message-type of this packet or -1 if the
                     message-type is undefined.
        """
        dhcp_message_type = self.getOption(53)
        if dhcp_message_type is None:
            return -1
        return dhcp_message_type[0]

    def getDHCPMessageTypeName(self):
        """
        Provides the DHCP message-type of this packet.
        
        :return str: The DHCP message-type of this packet.
        """
        return DHCP_TYPE_NAMES.get(self._getDHCPMessageType(), 'UNKNOWN_UNKNOWN')
        
    def isDHCPAckPacket(self):
        """
        Indicates whether this is an ACK packet.
        
        :return bool: True if this is an ACK packet.
        """
        return self._getDHCPMessageType() == 5

    def isDHCPDeclinePacket(self):
        """
        Indicates whether this is a DECLINE packet.
        
        :return bool: True if this is a DECLINE packet.
        """
        return self._getDHCPMessageType() == 4
        
    def isDHCPDiscoverPacket(self):
        """
        Indicates whether this is a DISCOVER packet.
        
        :return bool: True if this is a DISCOVER packet.
        """
        return self._getDHCPMessageType() == 1
        
    def isDHCPInformPacket(self):
        """
        Indicates whether this is an INFORM packet.
        
        :return bool: True if this is an INFORM packet.
        """
        return self._getDHCPMessageType() == 8
        
    def isDHCPLeaseActivePacket(self):
        """
        Indicates whether this is a LEASEACTIVE packet.
        
        :return bool: True if this is a LEASEACTIVE packet.
        """
        return self._getDHCPMessageType() == 13
        
    def isDHCPLeaseQueryPacket(self):
        """
        Indicates whether this is a LEASEQUERY packet.
        
        :return bool: True if this is a LEASEQUERY packet.
        """
        return self._getDHCPMessageType() == 10
        
    def isDHCPLeaseUnassignedPacket(self):
        """
        Indicates whether this is a LEASEUNASSIGNED packet.
        
        :return bool: True if this is a LEASEUNASSIGNED packet.
        """
        return self._getDHCPMessageType() == 11
        
    def isDHCPLeaseUnknownPacket(self):
        """
        Indicates whether this is a LEASEUNKNOWN packet.
        
        :return bool: True if this is a LEASEUNKNOWN packet.
        """
        return self._getDHCPMessageType() == 12
        
    def isDHCPOfferPacket(self):
        """
        Indicates whether this is an OFFER packet.
        
        :return bool: True if this is an OFFER packet.
        """
        return self._getDHCPMessageType() == 2
        
    def isDHCPNakPacket(self):
        """
        Indicates whether this is a NAK packet.
        
        :return bool: True if this is a NAK packet.
        """
        return self._getDHCPMessageType() == 6
        
    def isDHCPReleasePacket(self):
        """
        Indicates whether this is a RELEASE packet.
        
        :return bool: True if this is a RELEASE packet.
        """
        return self._getDHCPMessageType() == 7
        
    def isDHCPRequestPacket(self):
        """
        Indicates whether this is a REQUEST packet.
        
        :return bool: True if this is a REQUEST packet.
        """
        return self._getDHCPMessageType() == 3
        
    def _transformBase(self):
        """
        Sets and removes options from the packet to make it suitable for
        returning to the client.
        """
        self.setOption(FIELD_OP, [2])
        self.setOption(FIELD_HLEN, [6])
        
        self.deleteOption(FIELD_SECS)
        
        self.deleteOption(22) #maximum_datagram_reassembly_size
        self.deleteOption(43) #vendor_specific_information
        self.deleteOption(50) #requested_ip_address
        self.deleteOption(52) #overload
        self.deleteOption(55) #parameter_request_list
        self.deleteOption(57) #maximum_dhcp_message_size
        self.deleteOption(60) #vendor_class_identifier
        self.deleteOption(61) #client_identifier
        self.deleteOption(93) #client_system
        self.deleteOption(94) #client_ndi
        self.deleteOption(97) #uuid_guid
        self.deleteOption(118) #subnet_selection
        self.deleteOption(124) #vendor_class
        self.deleteOption(125) #vendor_specific
        
    def transformToDHCPAckPacket(self):
        """
        Transforms a packet received from a client into an ACK packet to be
        returned to the client.
        """
        self._transformBase()
        self.setOption(53, [5]) #dhcp_message_type
        
    def transformToDHCPLeaseActivePacket(self):
        """
        Transforms a packet received from a client into a LEASEACTIVE packet
        to be returned to the client.
        """
        self._transformBase()
        self.setOption(53, [13]) #dhcp_message_type
        
        self.deleteOption(FIELD_CIADDR)
        
        self.deleteOption(FIELD_FILE)
        self.deleteOption(FIELD_SNAME)
        
    def transformToDHCPLeaseUnassignedPacket(self):
        """
        Transforms a packet received from a client into a LEASEUNASSIGNED packet
        to be returned to the client.
        """
        self._transformBase()
        self.setOption(53, [11]) #dhcp_message_type
        
        self.deleteOption(FIELD_CIADDR)
        
        self.deleteOption(FIELD_FILE)
        self.deleteOption(FIELD_SNAME)
        
    def transformToDHCPLeaseUnknownPacket(self):
        """
        Transforms a packet received from a client into a LEASEUNKNOWN packet
        to be returned to the client.
        """
        self._transformBase()
        self.setOption(53, [12]) #dhcp_message_type
        
        self.deleteOption(FIELD_CIADDR)
        
        self.deleteOption(FIELD_FILE)
        self.deleteOption(FIELD_SNAME)
        
    def transformToDHCPOfferPacket(self):
        """
        Transforms a packet received from a client into an OFFER packet to be
        returned to the client.
        """
        self._transformBase()
        self.setOption(53, [2]) #dhcp_message_type
        
        self.deleteOption(FIELD_CIADDR)
        
    def transformToDHCPNakPacket(self):
        """
        Transforms a packet received from a client into a NAK packet to be
        returned to the client.
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
        Renders packet data in human-readable form.
        
        :return str: The packet's contents, in human-readable form.
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
        
        flags = []
        if self.getFlag(FLAGBIT_BROADCAST):
            flags.append('broadcast')
        output.append("\tflags: %(flags)s" % {
         'flags': ', '.join(flags),
        })
        
        for field in (
         FIELD_HOPS, FIELD_SECS,
         FIELD_XID,
         FIELD_SIADDR, FIELD_GIADDR, FIELD_CIADDR, FIELD_YIADDR,
         FIELD_SNAME, FIELD_FILE,
        ):
            (start, length) = DHCP_FIELDS[field]
            data = self._header[start:start + length]
            data = _FORMAT_CONVERSION_DESERIAL[DHCP_FIELDS_TYPES[field]](data)
            if field in (FIELD_SNAME, FIELD_FILE):
                data = data.rstrip('\x00')
            output.append("\t%(field)s: %(data)r" % {
             'field': field,
             'data': data,
            })
            
        output.append('')
        output.append("::Body::")
        for (option_id, data) in sorted(self._options.items()):
            result = None
            represent = False
            if option_id == 53: #dhcp_message_type
                result = self.getDHCPMessageTypeName()
            elif option_id == 55: #parameter_request_list
                result = ', '.join("%(id)03i:%(name)s" % {
                 'id': id,
                 'name': DHCP_OPTIONS_REVERSE.get(id, "unsupported"),
                } for id in self.getSelectedOptions())
            else:
                represent = True
                result = _FORMAT_CONVERSION_DESERIAL[DHCP_OPTIONS_TYPES[option_id]](data)
            output.append((represent and "\t[%(selected)s][%(id)03i] %(name)s: %(result)r" or "\t[-][%(id)03i] %(name)s: %(result)s") % {
             'selected': self.isSelectedOption(option_id) and 'X' or ' ',
             'id': option_id,
             'name': self._getOptionName(option_id),
             'result': result,
            })
        return '\n'.join(output)
        
