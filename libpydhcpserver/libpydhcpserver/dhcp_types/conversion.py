# -*- encoding: utf-8 -*-
"""
libpydhcpserver.dhcp_types.conversion
=====================================
Provides convenience functions used to convert from friendly data-types into
packet-insertable data-types and vice-versa.

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
"""
_IPv4 = None #: Placeholder for a deferred import ot avoid a circular reference.

def listToNumber(l):
    value = 0
    for (i, v) in enumerate(reversed(l)):
        value += v * (256 << (8 * i))
    return value
    
def listToInt(l):
    return listToNumber(l[:2])
    
def listToInts(l):
    ints = []
    for i in xrange(len(l) >> 1):
        p = i * 2
        ints.append(listToInt(l[p:p + 2]))
    return ints
    
def listToLong(l):
    return listToNumber(l[:4])
    
def listToLongs(l):
    longs = []
    for i in xrange(len(l) >> 2):
        p = i * 4
        longs.append(listToLong(l[p:p + 4]))
    return longs
    
def intToList(i):
    """
    A convenience function that converts an int into a pair of bytes.
    
    @type i: int
    @param i: The int value to convert.
    
    @rtype: list
    @return: The converted bytes.
    """
    return [
     i >> 8 & 0xFF,
     i & 0xFF,
    ]
    
def intsToList(l):
    """
    A convenience function that converts a sequence of ints into pairs of bytes.
    
    @type l: sequence
    @param l: The int values to convert.
    
    @rtype: list
    @return: The converted bytes.
    """
    pairs = []
    for i in l:
        pairs += intToList(i)
    return pairs
    
def longToList(l):
    """
    A convenience function that converts a long into a set of four bytes.
    
    @type l: int
    @param l: The long value to convert.
    
    @rtype: list
    @return: The converted bytes.
    """
    return [
     l >> 24 & 0xFF,
     l >> 16 & 0xFF,
     l >> 8 & 0xFF,
     l & 0xFF,
    ]
    
def longsToList(l):
    """
    A convenience function that converts a sequence of longs into a list of
    bytes.
    
    @type l: sequence
    @param l: The long values to convert.
    
    @rtype: list
    @return: The converted bytes.
    """
    bytes = []
    for i in l:
        bytes += longToList(i)
    return bytes
    
def strToList(s):
    """
    Converts the given string into an encoded byte format.
    
    @type s: basestring
    @param s: The string to be converted.
    
    @rtype: list
    @return: An encoded byte version of the given string.
    """
    return map(ord, s)
    
def strToPaddedList(s, l):
    """
    Converts the given string into an encoded byte format, exactly equal to the
    specified length.
    
    Strings longer than the given length will be truncated, while those shorter
    will be null-padded.
    
    @type s: basestring
    @param s: The string to be converted.
    @type l: int
    @param l: The length of the list.

    @rtype: list
    @return: An encoded byte version of the given string of the specified length.
    """
    padded_list = strToList(s)
    if len(padded_list) < l:
        padded_list += [0] * (l - len(padded_list))
    return padded_list[:l]
    
def listToStr(l):
    return ''.join(chr(i) for i in l)
    
def ipToList(ip):
    """
    Converts an IPv4 address into a collection of four bytes.
    
    @type ip: basestring
    @param ip: The IPv4 to process.
    
    @rtype: list
    @return: The IPv4 expressed as bytes.
    """
    global _IPv4
    if not _IPv4:
        from ipv4 import IPv4
        _IPv4 = IPv4
        
    if not isinstance(ip, _IPv4):
        ip = _IPv4(ip)
    return list(ip)
    
def ipsToList(ips):
    """
    Converts a comma-delimited list of IPv4s into bytes.
    
    @type ips: basestring
    @param ips: The list of IPv4s to process.
    
    @rtype: list
    @return: A collection of bytes corresponding to the given IPv4s.
    """
    if isinstance(ips, StringTypes):
        tokens = ips.split(',')
    else:
        tokens = ips
        
    bytes = []
    for ip in ips:
        bytes += ipToList(ip)
    return bytes
    
def listToIP(l):
    global _IPv4
    if not _IPv4:
        from ipv4 import IPv4
        _IPv4 = IPv4
        
    return _IPv4(l)
    
def listToIPs(l):
    ips = []
    for i in xrange(len(l) / 4):
        p = i * 4
        ips.append(listToIP(l[p:p + 4]))
    return ips
    
    