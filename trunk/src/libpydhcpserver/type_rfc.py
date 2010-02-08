# -*- encoding: utf-8 -*-
"""
libpydhcpserver module: type_rfc

Purpose
=======
 Defines the libpydhcpserver-specific RFC types.
 
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
 
 (C) Neil Tallim, 2010 <flan@uguu.ca>
 (C) Mathieu Ignacio, 2008 <mignacio@april.org>
"""
import type_ipv4

import src.dhcp

class _rfc(object):
	_value = None
	
	def getValue(self):
		return self._value
		
	def __hash__(self):
		return self._value.__hash__()
		
	def __repr__(self):
		return repr(self._value)
		
	def __nonzero__(self) :
		return 1
		
	def __cmp__(self, other):
		if self._value == other:
			return 0
		return 1
		
		
def _rfc1035Parse(domain_name):
	bytes = []
	for fragment in domain_name.split('.'):
		bytes += [len(fragment)] + [ord(c) for c in fragment]
	return bytes + [0]
	
	
class rfc2610_78(_rfc):
	def __init__(self, mandatory, data):
		self._value = [int(mandatory)]
		for token in [tok for tok in [t.strip() for t in data.split(',')] if tok]:
			self._value += type_ipv4.ipv4(token).list()
			
class rfc2610_79(_rfc):
	def __init__(self, mandatory, data):
		self._value = [int(mandatory)] + [ord(c) for c in data.encode('utf-8')]
		
		
class rfc3361_120(_rfc):
	def __init__(self, data):
		ip_4_mode = False
		dns_mode = False
		
		self._value = []
		for token in [tok for tok in [t.strip() for t in data.split(',')] if tok]:
			try:
				self._value += type_ipv4.ipv4(token).list()
				ip_4_mode = True
			except ValueError:
				self._value += _rfc1035Parse(token)
				dns_mode = True
				
		if not ip_4_mode ^ dns_mode:
			raise ValueError("RFC3361 argument '%(data)s is not valid: contains both IPv4 and DNS-based entries" % {
			 'data': data,
			})
			
		self._value.insert(0, int(ip_4_mode))
		
		
class rfc3397_119(_rfc):
	def __init__(self, data):
		self._value = []
		for token in [tok for tok in [t.strip() for t in data.split(',')] if tok]:
			self._value += _rfc1035Parse(token)
			
class rfc4174_83(_rfc):
	def __init__(self, isns_functions, dd_access, admin_flags, isns_security, ips):
		isns_functions = src.dhcp.intToList(isns_functions)
		dd_access = src.dhcp.intToList(dd_access)
		admin_flags = src.dhcp.intToList(admin_flags)
		isns_security = src.dhcp.longToList(isns_security)
		
		self._value = isns_functions + dd_access + admin_flags + isns_security
		for token in [tok for tok in [t.strip() for t in ips.split(',')] if tok]:
			self._value += type_ipv4.ipv4(token).list()
			