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

(C) Neil Tallim, 2014 <flan@uguu.ca>
"""
try:
    from types import StringTypes
except ImportError: #py3k
    StringTypes = (str,)

_IPv4 = None #: Placeholder for a deferred import ot avoid a circular reference.

def listToNumber(l):
    """
    Sums a sequence of bytes in big-endian order, producing an integer.
    
    :param sequence l: A sequence of ints, between ``0`` and ``255``.
    :return int: The corresponding value.
    """
    value = 0
    for (i, v) in enumerate(reversed(l)):
        value += v << (8 * i)
    return value
    
def listToInt(l):
    """
    Converts a pair of bytes, in big-endian order, into an integer.
    
    :param sequence l: A sequence of ints, between ``0`` and ``255``. If longer
        than two, only the head is used; if less than two, zero-padded to LSD.
    :return int: The corresponding value.
    """
    return listToNumber(l[:2])
    
def listToInts(l):
    """
    Converts pairs of bytes, in big-endian order, into integers.
    
    :param sequence l: A sequence of ints, between ``0`` and ``255``. If not a
        multiple of two, zero-padded to LSD.
    :return list: A list of ints corresponding to the byte-pairs.
    """
    ints = []
    for i in xrange(len(l) >> 1):
        p = i * 2
        ints.append(listToInt(l[p:p + 2]))
    return ints
    
def listToLong(l):
    """
    Converts a quartet of bytes, in big-endian order, into an integer.
    
    :param sequence l: A sequence of ints, between ``0`` and ``255``. If longer
        than four, only the head is used; if less than four, zero-padded to LSD.
    :return int: The corresponding value.
    """
    return listToNumber(l[:4])
    
def listToLongs(l):
    """
    Converts quartets of bytes, in big-endian order, into integers.
    
    :param sequence l: A sequence of ints, between ``0`` and ``255``. If not a
        multiple of four, zero-padded to LSD.
    :return list: A list of ints corresponding to the byte-quartets.
    """
    longs = []
    for i in xrange(len(l) >> 2):
        p = i * 4
        longs.append(listToLong(l[p:p + 4]))
    return longs
    
def intToList(i):
    """
    Converts an integer into a pair of bytes in big-endian order.
    
    :param int i: The integer to be converted. If outside the range of ``0`` to
        ``65535``, only the low-order sixteen bits are considered.
    :return list(2): The converted value.
    """
    return [
     i >> 8 & 0xFF,
     i & 0xFF,
    ]
    
def intsToList(l):
    """
    Converts a sequence of integers into pairs of bytes in big-endian order.
    
    :param sequence l: The sequence to be converted. If any values are outside
        the range of ``0`` to ``65535``, only the low-order sixteen bits are
        considered.
    :return list: The converted values.
    """
    pairs = []
    for i in l:
        pairs += intToList(i)
    return pairs
    
def longToList(l):
    """
    Converts an integer into a quartet of bytes in big-endian order.
    
    :param int l: The integer to be converted. If outside the range of ``0`` to
        ``4294967296``, only the low-order thirty-two bits are considered.
    :return list(4): The converted value.
    """
    return [
     l >> 24 & 0xFF,
     l >> 16 & 0xFF,
     l >> 8 & 0xFF,
     l & 0xFF,
    ]
    
def longsToList(l):
    """
    Converts a sequence of integers into quartets of bytes in big-endian order.
    
    :param sequence l: The sequence to be converted. If any values are outside
        the range of ``0`` to ``4294967296``, only the low-order thirty-two
        bits are considered.
    :return list: The converted values.
    """
    bytes = []
    for i in l:
        bytes += longToList(i)
    return bytes
    
def listToStr(l):
    """
    Converts a sequence of bytes into a byte-string.
    
    :param sequence l: The bytes to be converted.
    :return str: The converted byte-string.
    """
    return ''.join(chr(i) for i in l)
    
def strToList(s):
    """
    Converts a string into a sequence of bytes.
    
    This will also handle unicode strings, so sanitise all input.
    
    :param str s: The string to be converted.
    :return list: A sequence of bytes.
    """
    return [ord(c) for c in s.encode('utf-8')]
    
def strToPaddedList(s, l):
    """
    Converts a string into a sequence of bytes, with a fixed length.
    
    This will also handle unicode strings, so sanitise all input.
    
    :param str s: The string to be converted.
    :param int l: The length of the resulting list.
    :return list: A sequence of bytes of length ``l``, truncated or null-padded
        as appropriate.
    """
    padded_list = strToList(s)
    if len(padded_list) < l:
        padded_list += [0] * (l - len(padded_list))
    return padded_list[:l]
    
def listToIP(l):
    """
    Converts almost anything into an IPv4 address.
    
    :param sequence(4) l: The bytes to be converted.
    :return: The equivalent IPv4 address.
    :except ValueError: The list could not be processed.
    """
    global _IPv4
    if not _IPv4:
        from ipv4 import IPv4
        _IPv4 = IPv4
        
    return _IPv4(l)
    
def listToIPs(l):
    """
    Converts almost anything into IPv4 addresses.
    
    :param sequence l: The bytes to be converted, as a flat sequence with
        length a multiple of four.
    :return list: The equivalent IPv4 addresses.
    :except ValueError: The list could not be processed.
    """
    ips = []
    for i in xrange(len(l) / 4):
        p = i * 4
        ips.append(listToIP(l[p:p + 4]))
    return ips
    
def ipToList(ip):
    """
    Converts an IPv4 address into a list of four bytes in big-endian order.
    
    :param object ip: Any valid IPv4 format (string, 32-bit integer, list of
                      bytes, :class:`IPv4 <dhcp_types.IPv4>`).
    :return list(4): The converted address.
    :except ValueError: The IP could not be processed.
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
    Converts a IPv4 addresses into a flat list of multiples of four bytes in
    big-endian order.
    
    :param list ips: A list of any valid IPv4 formats (string, 32-bit integer,
        list of bytes, :class:`IPv4 <dhcp_types.IPv4>`).
    :return list: The converted addresses.
    :except ValueError: The IPs could not be processed.
    """
    if isinstance(ips, StringTypes):
        tokens = ips.split(',')
    else:
        tokens = ips
        
    bytes = []
    for ip in tokens:
        bytes += ipToList(ip)
    return bytes
    
