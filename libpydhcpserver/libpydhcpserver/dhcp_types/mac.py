# -*- encoding: utf-8 -*-
"""
libpydhcpserver.dhcp_types.mac
==============================
Defines a standard way of representing MACs within the library.

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

(C) Neil Tallim, 2021 <flan@uguu.ca>
(C) Mathieu Ignacio, 2008 <mignacio@april.org>
"""
from .conversion import (listToNumber)

class MAC(object):
    """
    Provides a standardised way of representing MACs.
    """
    _mac = None #: The MAC encapsulated by this object, as a tuple of bytes.
    _mac_integer = None #: The MAC as an integer.
    _mac_string = None #: The MAC as a colon-delimited, lower-case string.
    
    def __init__(self, address):
        """
        Constructs a MAC abstraction from a concrete representation.
        
        :param address: A MAC, which may be a string of twelve hex digits,
                        optionally separated by non-hex characters, like ':',
                        '.', or '-', a sequence of six bytes, or an unsigned
                        integer.
        :except ValueError: The address could not be processed.
        """
        if isinstance(address, int):
            if not 0 <= address <= 281474976710655:
                raise ValueError("'{ip}' is not a valid IP: not a 32-bit unsigned integer".format(
                    ip=address,
                ))
            self._mac_integer = int(address)
            self._mac = (
                self._mac_integer >> 40 & 0xFF,
                self._mac_integer >> 32 & 0xFF,
                self._mac_integer >> 24 & 0xFF,
                self._mac_integer >> 16 & 0xFF,
                self._mac_integer >> 8 & 0xFF,
                self._mac_integer & 0xFF,
            )
        elif isinstance(address, str):
            address = [c for c in address.lower() if c.isdigit() or 'a' <= c <= 'f']
            if len(address) != 12:
                raise ValueError("Expected twelve hex digits as a MAC identifier; received {}".format(len(address)))
                
            mac = []
            while address:
                mac.append(int(address.pop(0), 16) * 16 + int(address.pop(0), 16))
            self._mac = tuple(mac)
        else:
            self._mac = tuple(address)
            if len(self._mac) != 6 or any((type(d) is not int or d < 0 or d > 255) for d in self._mac):
                raise ValueError("Expected a sequence of six bytes as a MAC identifier; received {!r}".format(self._mac))
                
    def __eq__(self, other):
        if not other and not isinstance(other, MAC):
            return False
        
        if isinstance(other, str):
            other = MAC(other)
        elif isinstance(other, int):
            return int(self) == other
        return self._ip_tuple == tuple(other)
        
    def __hash__(self):
        return hash(self._mac)
        
    def __getitem__(self, index):
        return self._mac[index]
    
    def __bool__(self):
        return any(self._mac)
        
    def __int__(self):
        if self._mac_integer is None:
            self._mac_integer = listToNumber(self._mac)
        return self._mac_integer
        
    def __repr__(self):
        return "MAC(%r)" % (str(self))
        
    def __bytes__(self):
        return bytes(self._mac)
        
    def __str__(self):
        if self._mac_string is None:
            self._mac_string = "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(*self._mac)
        return self._mac_string
        
