# -*- encoding: utf-8 -*-
"""
types.ipv4
==========
Defines a standard way of representing IPv4s within the library.

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
try:
    from types import StringTypes
except ImportError: #py3k
    StringTypes = (str,)
    
IntegerTypes = (int,)
try:
    IntegerTypes = (int, long)
except ImportError: #py3k
    pass
    
import rfc

class IPv4(object):
    """
    Evaluates and encodes an IPv4 for use as part of a DHCP packet. 
    """
    _ip = None #An IPv4 as an integer
    _ip_tuple = None #An IPv4 as a quadruple of bytes
    _ip_string = None #An IPv4 as a dotted quad
    
    def __init__(self, address):
        """
        Constructs an IPv4 from `address`, which may be a dotted quad, a
        quadruple of bytes, or a 32-bit, unsigned integer.
        """
        if isinstance(address, IntegerTypes):
            if not 0 <= address <= 4294967295:
                raise ValueError("'%(ip)i' is not a valid IP: not a 32-bit unsigned integer" % {
                 'ip': address,
                })
                self._ip = int(address)
                self._ip_tuple = tuple(rfc.longToList(self._ip))
        else:
            if isinstance(address, StringTypes):
                octets = (i.strip() for i in address.split('.'))
            else:
                octets = address
                
            try:
                octets = [int(i) for i in octets][:4]
            except Exception:
                raise ValueError("%(ip)r is not a valid IPv4: non-integer data supplied" % {
                 'ip': address,
                })
            else:
                if len(octets) < 4:
                    raise ValueError("%(ip)r is not a valid IPv4: length < 4" % {
                     'ip': address,
                    })
                    
                if any(True for i in octets if i < 0 or i > 255):
                    raise ValueError("%(ip)r is not a valid IPv4: non-byte values present" % {
                     'ip': address,
                    })
                    
                self._ip_tuple = tuple(octets)
                
    def __cmp__(self, other):
        if not other:
            return 1
        if isinstance(other, StringTypes):
            other = IPv4(other)
        if isinstance(other, IPv4):
            return cmp(str(self), str(other))
        if isinstance(other, IntegerTypes):
            return cmp(int(self), other)
        return cmp(self._ip_tuple, tuple(other))
        
    def __hash__(self):
        return hash(self._ip_tuple)
        
    def __getitem__(self, index):
        return self._ip_tuple[index]
        
    def __nonzero__(self):
        return any(self._ip_tuple)
        
    def __int__(self):
        if self._ip is None:
            self._ip = rfc.listToLong(self._ip_tuple)
        return self._ip
        
    def __long__(self):
        return long(int(self))
        
    def __repr__(self):
        return str(self)
        
    def __str__(self):
        if not self._ip_string:
            self._ip_string = "%i.%i.%i.%i" % self._ip_tuple
        return self._ip_string
        
