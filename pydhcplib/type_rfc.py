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

class _rfc(object):
	_value = None
	
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
		
		
def _rfc1035Parse(domain_name, terminator=[0]):
	bytes = []
	for fragment in domain_name.split('.'):
		bytes += [len(fragment)] + [ord(c) for c in fragment]
	return bytes + terminator
	
class rfc3361(_rfc):
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
				bytes += _rfc1035Parse(token)
				dns_mode = True
				
		if not ip_4_mode ^ dns_mode:
			raise ValueError("RFC3361 argument '%(data)s is not valid: contains both IPv4 and DNS-based entries" % {
			 'data': data,
			})
			
		self._value = [int(ip_4_mode)] + bytes
		
class rfc3397(_rfc):
	def __init__(self, data):
		tokens = [token for token in [t.strip() for t in data.split(',')] if token]
		bytes = []
		
		preceding_tokens = []
		for token in tokens:
			longest_match = 0
			longest_match_pos = 0
			longest_match_offset = 0
			fragments = reversed(token.split('.'))
			for (i, (old_fragments, old_bytes)) in enumerate(preceding_tokens):
				match = 0
				offset = 0
				for (new, old) in zip(fragments, reversed(old_fragments)):
					if new == old:
						match += 1
						offset += len(old)
					else:
						break
				if match > longest_match:
					longest_match = match
					longest_match_pos = i
					longest_match_offset = sum([len(f) for f in old_fragments]) - offset
					
			if longest_match:
				offset = longest_match_offset + sum([len(old_bytes) for (old_fragments, old_bytes) in preceding_tokens[:longest_match_pos]])
				bytes += _rfc1035Parse(token, [(offset / 256) % 256, offset % 256])
			else:
				bytes += _rfc1035Parse(token)
			preceding_tokens.append((fragments, new_bytes))
			
		self._value = bytes
		
