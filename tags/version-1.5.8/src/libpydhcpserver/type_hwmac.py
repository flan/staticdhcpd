# -*- encoding: utf-8 -*-
"""
libpydhcpserver module: type_hwmac

Purpose
=======
 Defines the libpydhcpserver-specific hwmac type.
 
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
from binascii import unhexlify, hexlify

class hwmac(object):
    """
    Evaluates and encodes a MAC for use as part of a DHCP packet. 
    """
    _hw_numlist = None #: An encoded list of bytes.
    _hw_string = None #: A human-readable MAC.
    
    def __init__(self, data="00:00:00:00:00:00"):
        """
        Accepts data and ensures that both human-readable and packet-encodable
        values are made available.
        
        @type data: str|list|tuple
        @param data: The data to be processed.
        
        @raise TypeError: Unsupported data-type was supplied.
        @raise ValueError: Invalid data supplied.
        """
        if type(data) == str:
            self._hw_string = data.strip()
            self._stringToNumlist()
            self._checkNumList()
        elif type(data) in (list, tuple):
            self._hw_numlist = list(data)
            self._checkNumList()
            self._numlistToString()
        else:
            raise TypeError('Expected str or [int]; got %(type)s' % {
             'type': type(data),
            })
            
    def _checkNumList(self):
        """
        Validates the MAC address contained within this object.
        
        @raise TypeError: Unsupported data-type was supplied.
        @raise ValueError: Invalid data supplied.
        """
        if not len(self._hw_numlist) == 6:
            raise ValueError("Expected six octets; received %(count)i" % {
             'count': len(self._hw_numlist),
            })
        for part in self._hw_numlist:
            if not type(part) == int:
                raise TypeError('Expected int; got %(type)s' % {
                 'type': type(part),
                })
            if part < 0 or part > 255:
                raise ValueError("Expected 0 <= x <= 255; received %(x)i" % {
                 'x': part,
                })
                
    # Convert NumList type to String type
    def _numlistToString(self):
        """
        Converts a collection of bytes into a human-readable MAC address.
        """
        self._hw_string = ":".join(map(hexlify, map(chr, self._hw_numlist)))
        
    def _stringToNumlist(self):
        """
        Converts a human-readable MAC address into a collection of bytes.
        """
        self._hw_string = self._hw_string.replace("-", ":").replace(".", ":").lower()
        self._hw_numlist = [ord(unhexlify(twochar)) for twochar in self._hw_string.split(":")]
        
    def list(self):
        """
        Returns the packet-encodable data contained within this object.
        
        @rtype: list
        @return: A collection of bytes.
        """
        return self._hw_numlist
        
    def str(self):
        """
        Returns the human-readable data contained within this object.
        
        @rtype: str
        @return: A human-readable value.
        """
        return self._hw_string
        
    def __cmp__(self, other) :
        if self._hw_string == other:
            return 0
        return 1
        
    def __hash__(self):
        return self._hw_string.__hash__()
        
    def __nonzero__(self) :
        if not self._hw_string == "00:00:00:00:00:00":
            return 1
        return 0
        
    def __repr__(self) :
        return self._hw_string
        
