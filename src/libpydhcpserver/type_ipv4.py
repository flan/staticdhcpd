# -*- encoding: utf-8 -*-
"""
libpydhcpserver module: type_ipv4

Purpose
=======
 Defines the libpydhcpserver-specific ipv4 type.
 
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
# Check if _ip_numlist is valid.
def checkNumList(value):
    """
    Ensures that the given value is made up of four single bytes.
    
    @type value: sequence
    @param value: The value to be tested.
    
    @rtype: bool
    @return: True if validation succeeds.
    """
    if not len(value) == 4:
        return False
    for part in value:
        if not 0 <= part <= 255:
            return False
    return True
    
def checkString(value):
    """
    Ensures that the given value is made up of four dot-delimited single bytes.
    
    @type value: basestring
    @param value: The value to be tested.
    
    @rtype: bool
    @return: True if validation succeeds.
    """
    octets = value.strip().split('.')
    if not len(octets) == 4:
        return False
    for o in octets:
        if not o.isdigit():
            return False
        if not 0 <= int(o) <= 255:
            return False
    return True
    
class ipv4(object):
    """
    Evaluates and encodes an IPv4 for use as part of a DHCP packet. 
    """
    _ip_long = None #: A long-encoded IPv4.
    _ip_numlist = None #: An encoded list of bytes.
    _ip_string = None #: A human-readable string.
    
    def __init__(self, data="0.0.0.0"):
        """
        Accepts data and ensures that both human-readable and packet-encodable
        values are made available.
        
        @type data: str|list|tuple
        @param data: The data to be processed.
        
        @raise TypeError: Unsupported data-type was supplied.
        @raise ValueError: Invalid data supplied.
        """
        if type(data) == str:
            if not checkString(data):
                raise ValueError("'%(ip)s' is not a valid IP" % {
                 'ip': data,
                })
            self._ip_string = data
            self._stringToNumlist()
            self._numlistToLong()
        elif type(data) in (list, tuple):
            if not checkNumList(data):
                raise ValueError("'%(ip)s' is not a valid IP" % {
                 'ip': str(data),
                })
            self._ip_numlist = data
            self._numlistToString()
            self._numlistToLong()
        elif type(data) in (int, long):
            if not 0 <= data <= 4294967295:
                raise ValueError("'%(ip)i' is not a valid IP" % {
                 'ip': data,
                })
            self._ip_long = data
            self._longToNumlist()
            self._numlistToString()
        else:
            raise TypeError('Expected str, list, or long; got %(type)s' % {
             'type': ip_type,
            })
            
    def _longToNumlist(self):
        """
        Converts a long value into a collection of bytes.
        """
        self._ip_numlist = [self._ip_long >> 24 & 0xFF]
        self._ip_numlist.append(self._ip_long >> 16 & 0xFF)
        self._ip_numlist.append(self._ip_long >> 8 & 0xFF)
        self._ip_numlist.append(self._ip_long & 0xFF)
        
    def _numlistToLong(self):
        """
        Converts a collection of bytes into a long value.
        """
        self._ip_long = sum([x * 256 ** i for (i, x) in enumerate(reversed(self._ip_numlist))])
        
    def _numlistToString(self):
        """
        Converts a collection of bytes into a human-readable string.
        """
        self._ip_string = ".".join(map(str, self._ip_numlist))
        
    def _stringToNumlist(self):
        """
        Converts an IP string into a collection of bytes.
        """
        self._ip_numlist = map(int, self._ip_string.split('.'))
        
    def int(self):
        """
        Returns the integer data contained within this object.
        
        @rtype: int
        @return: A long value.
        """
        return self._ip_long
        
    def list(self):
        """
        Returns the packet-encodable data contained within this object.
        
        @rtype: list
        @return: A collection of bytes.
        """
        return self._ip_numlist
        
    def str(self):
        """
        Returns the human-readable data contained within this object.
        
        @rtype: str
        @return: A human-readable value.
        """
        return self._ip_string
        
    def __cmp__(self,other):
        return cmp(self._ip_long, other._ip_long)
        
    def __hash__(self):
        return self._ip_long.__hash__()
        
    def __nonzero__(self):
        if self._ip_long:
            return 1
        return 0
        
    def __repr__(self):
        return self._ip_string
        
