# -*- encoding: utf-8 -*-
"""
pydhcplib module: type_hwmac

Purpose
=======
 Defines the pydhcplib-specific hwmac type.
 
Legal
=====
 This file is part of pydhcplib.
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
 
 (C) Mathieu Ignacia, 2008 <mignacio@april.org>
"""
from binascii import unhexlify,hexlify

# Check and convert hardware/nic/mac address type
class hwmac(object):
	def __init__(self, value="00:00:00:00:00:00"):
		hw_type = type(value)
		if hw_type == str:
			value = value.strip()
			self._hw_string = value
			self._StringToNumlist(value)
			self._CheckNumList()
		elif hw_type in (list, tuple):
			self._hw_numlist = value
			self._CheckNumList()
			self._NumlistToString()
		else:
			raise TypeError('hwmac init : expected str or list; got %(type)s' % {'type': hw_type,})
			
	# Check if _hw_numlist is valid and raise error if not.
	def _CheckNumList(self):
		if not len(self._hw_numlist) == 6:
			raise ValueError("hwmac : expected six octets; received %(count)i" % {'count': len(self._hw_numlist),})
		for part in self._hw_numlist:
			if not type(part) == int:
				raise TypeError('hwmac checknumlist : expected int; got %(type)s' % {'type': type(part),})
			if part < 0 or part > 255:
				raise ValueError("hwmac : expected 0 <= x <= 255; received %(x)i" % {'x': part,})
		return True
		
	def _StringToNumlist(self,value):
		self._hw_string = self._hw_string.replace("-", ":").replace(".", ":")
		self._hw_string = self._hw_string.lower()
		
		self._hw_numlist = [ord(unhexlify(twochar)) for twochar in self._hw_string.split(":")]
		
	# Convert NumList type to String type
	def _NumlistToString(self):
		self._hw_string = ":".join(map(hexlify, map(chr, self._hw_numlist)))
		
	# Convert String type to NumList type
	def str(self):
		return self._hw_string
		
	# return octet list (useful for DhcpPacket class)
	def list(self):
		return self._hw_numlist
		
	def __hash__(self):
		return self._hw_string.__hash__()
		
	def __repr__(self) :
		return self._hw_string
		
	def __cmp__(self,other) :
		if self._hw_string == other:
			return 0
		return 1
		
	def __nonzero__(self) :
		if not self._hw_string == "00:00:00:00:00:00":
			return 1
		return 0
		