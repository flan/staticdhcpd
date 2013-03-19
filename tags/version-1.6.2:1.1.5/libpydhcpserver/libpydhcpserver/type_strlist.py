# -*- encoding: utf-8 -*-
"""
libpydhcpserver module: type_strlist

Purpose
=======
 Defines the libpydhcpserver-specific strlist type.
 
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
class strlist(object):
    """
    Evaluates and encodes a string for use as part of a DHCP packet. 
    """
    _list = None #: An encoded list of characters.
    _str = None #: A human-reaable string.
    
    def __init__(self, data=""):
        """
        Accepts data and ensures that both human-readable and packet-encodable
        values are made available.
        
        @type data: str|list|tuple
        @param data: The data to be processed.
        
        @raise TypeError: Unsupported data-type was supplied.
        @raise ValueError: Invalid data supplied.
        """
        if type(data) == str:
            self._str = data
            self._list = map(ord, self._str)
        elif type(data) in (list, tuple):
            self._list = list(data)
            self._str = ''.join(map(chr, self._list))
        else:
            raise TypeError('Expected str or [int]; got %(type)s' % {
             'type': type(data),
            })
            
    def list(self):
        """
        Returns the packet-encodable data contained within this object.
        
        @rtype: list
        @return: A collection of bytes.
        """
        return self._list
        
    def str(self):
        """
        Returns the human-readable data contained within this object.
        
        @rtype: str
        @return: A human-readable value.
        """
        return self._str
        
    def __cmp__(self, other):
        if self._str == other:
            return 0
        return 1
        
    def __hash__(self):
        return self._str.__hash__()
        
    def __nonzero__(self) :
        if self._str:
            return 1
        return 0
        
    def __repr__(self):
        return self._str
        
