# -*- encoding: utf-8 -*-
"""
libpydhcpserver.dhcp_types.ipv4
===============================
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

(C) Neil Tallim, 2014 <flan@uguu.ca>
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
    
from conversion import (longToList, listToLong)

_MAX_IP_INT = 4294967295

class IPv4(object):
    """
    An abstract IPv4 address that can be realised as a sequence of bytes, a
    dotted quad, or an unsigned, 32-bit integer, as needed.
    """
    _ip = None #: An IPv4 as an integer.
    _ip_tuple = None #: An IPv4 as a quadruple of bytes.
    _ip_string = None #: An IPv4 as a dotted quad.
    
    def __init__(self, address):
        """
        Constructs an IPv4 abstraction from a concrete representation.
        
        :param address: An IPv4, which may be a dotted quad, a quadruple of
                        bytes, or a 32-bit, unsigned integer.
        :except ValueError: The address could not be processed.
        """
        if isinstance(address, IntegerTypes):
            if not 0 <= address <= _MAX_IP_INT:
                raise ValueError("'%(ip)i' is not a valid IP: not a 32-bit unsigned integer" % {
                 'ip': address,
                })
            self._ip = int(address)
            self._ip_tuple = tuple(longToList(self._ip))
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
        if not other and not isinstance(other, IPv4):
            return 1
        if isinstance(other, StringTypes):
            other = IPv4(other)
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
            self._ip = listToLong(self._ip_tuple)
        return self._ip
        
    def __long__(self):
        return long(int(self))
        
    def __repr__(self):
        return "IPv4(%r)" % (str(self))
        
    def __str__(self):
        if not self._ip_string:
            self._ip_string = "%i.%i.%i.%i" % self._ip_tuple
        return self._ip_string
        
    def isSubnetMember(self, address, prefix):
        """
        Evaluates whether this IPv4 address is a member of the specifed subnet.
        
        :param address: An IPv4, which may be a dotted quad, a quadruple of
                        bytes, or a 32-bit, unsigned integer.
        :param prefix: A subnet mask or CIDR prefix, like `'255.255.255.0'`
                       or `24`.
        :return bool: `True` if this IPv4 is a member of the subnet.
        :except ValueError: The address or prefix could not be processed.
        """
        if isinstance(prefix, IntegerTypes):
            if 0 <= prefix <= 32:
                mask = (_MAX_IP_INT << (32 - prefix))
            else:
                raise ValueError("Invalid CIDR prefix: %(prefix)i" % {
                 'prefix': prefix,
                })
        else:
            mask = int(IPv4(prefix))
        return mask & int(IPv4(address)) == mask & int(self)
        
    @classmethod
    def parseSubnet(cls, subnet):
        """
        Splits a subnet-specifier written in common "ip/mask" notation into its
        constituent parts, allowing patterns like 
        `(address, prefix) = IPv4.parseSubnet("10.50.0.0/255.255.0.0")` and
        `<IPv4>.isSubnetMember(*<IPv4>.parseSubnet("192.168.0.0/24"))`.
        
        :param subnet: A string, using dotted-quad-slash-notation, with either
                       an IPv4 mask or a CIDR integer as its complement.
        :return tuple(2): The address and prefix components of the subnet.
        :except ValueError: The subnet could not be interpreted.
        """
        (address, prefix) = subnet.split('/', 1)
        if prefix.isdigit():
            return (address, int(prefix))
        return (address, prefix)
        