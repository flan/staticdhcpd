# -*- encoding: utf-8 -*-
"""
pydhcplib module: type_rfc

Purpose
=======
 Defines the pydhcplib-specific RFC types.
 
Legal
=====
 This file is new to pydhcplib, designed as a necessary requirement of
 staticDHCPd.
 pydhcplib is free software; you can redistribute it and/or modify
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
"""
import type_ipv4

class rfc3361(object):
	def __init__(self, data):
		ip_4_mode = False
		dns_mode = False
		
		tokens = [token for token in [t.strip() for t in data.split(',')] if token]
		bytes = []
		
		for token in tokens:
			try:
				ip_4 = type_ipv4.ipv4(token)
				bytes += ip_4.list()
				
				ip_4_mode = True
			except ValueError:
				for fragment in token.split('.'):
					bytes += [len(fragment)] + [ord(c) for c in fragment]
				bytes.append(0)
				dns_mode = True
				
		if not ip_4_mode ^ dns_mode:
			raise ValueError("RFC3361 argument '%(data)s is not valid: contains both IPv4 and DNS-based entries" % {
			 'data': data,
			})
			
		self._value = [int(ip_4_mode)] + bytes
		
	def getValue(self):
		return self._value
		
	def __hash__(self):
		return self._value.__hash__()
		
	def __repr__(self):
		return self._value
		
	def __nonzero__(self) :
		return 1
		
	def __cmp__(self, other):
		if self._value == other:
			return 0
		return 1
		