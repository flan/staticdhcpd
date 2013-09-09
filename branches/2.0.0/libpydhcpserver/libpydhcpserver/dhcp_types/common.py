# -*- encoding: utf-8 -*-
"""
types.common
============
Defines common data-access methods.

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
def listToNumber(l):
    value = 0
    for (i, v) in enumerate(reversed(l)):
        value += v * (256 ** i)
    return value
    
def listToInt(l):
    return listToNumber(l[:2])
    
def listToLong(l):
    return listToNumber(l[:4])
    
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
    