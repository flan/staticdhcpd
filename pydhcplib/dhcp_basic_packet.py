# -*- encoding: utf-8 -*-
"""
pydhcplib module: dhcp_basic_packet

Purpose
=======
 Base class to encode/decode dhcp packets.
 
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
 
 (C) Mathieu Ignacio, 2008 <mignacio@april.org>
"""
import operator
from struct import unpack
from struct import pack

from dhcp_constants import *

class DhcpBasicPacket(object):
	def __init__(self):
		self.packet_data = [0]*240
		self.options_data = {}
		self.packet_data[236:240] = MagicCookie
		self.source_address = False
		
	def IsDhcpPacket(self):
		if not self.packet_data[236:240] == MagicCookie:
			return False
		return True
		
	def CheckType(self, variable):
		# Check if variable is a list with int between 0 and 255
		if type(variable) == list:
			for each in variable:
				if not type(each) == int or each < 0 or each > 255:
					return False
			return True
		else:
			return False
			
	def DeleteOption(self,name):
		if DhcpFields.has_key(name):
			dhcp_field = DhcpFields[name]
			begin = dhcp_field[0]
			end = dhcp_field[0] + dhcp_field[1]
			self.packet_data[begin:end] = [0]*dhcp_field[1]
			return True
		elif self.options_data.has_key(name) :
			del self.options_data[name]
			return True
		return False
		
	def GetOption(self, name):
		if DhcpFields.has_key(name):
			option_info = DhcpFields[name]
			return self.packet_data[option_info[0]:option_info[0] + option_info[1]]
		elif self.options_data.has_key(name):
			return self.options_data[name]
		return []
		
	def SetOption(self,name,value):
		# Basic value checking: does the value list have a valid length?
		# has value list a correct length
		if DhcpFields.has_key(name):
			dhcp_field = DhcpFields[name]
			if not len(value) == dhcp_field[1]:
				raise ValueError("pydhcplib.dhcp_basic_packet.setoption error : bad option length: %(name)s" % {'name': name}) 
			begin = dhcp_field[0]
			end = dhcp_field[0] + dhcp_field[1]
			self.packet_data[begin:end] = value
			return True
		elif DhcpOptions.has_key(name):
			# fields_specs : {'option_code':fixed_length,minimum_length,multiple}
			# if fixed_length == 0 : minimum_length and multiple apply
			# else : forget minimum_length and multiple 
			# multiple : length MUST be a multiple of 'multiple'
			# FIXME : this definition should'nt be in dhcp_constants ?
			fields_specs = {
			 "ipv4":[4,0,1], "ipv4+":[0,4,4],
			 "string":[0,0,1], "bool":[1,0,1],
			 "char":[1,0,1], "16-bits":[2,0,1],
			 "32-bits":[4,0,1], "identifier":[0,2,1],
			 "RFC3397":[0,4,1],"none":[0,0,1],"char+":[0,1,1]
			}
			specs = fields_specs[DhcpOptionsTypes[DhcpOptions[name]]]
			length = len(value)
			if (not specs[0] == 0 and specs == length) or (specs[1] <= length and length % specs[2] == 0):
				self.options_data[name] = value
				return True
			else:
				return False
		raise ValueError("pydhcplib.dhcp_basic_packet.setoption error : unknown option: %(name)s" % {'name': name})
		
	def IsOption(self,name):
		if self.options_data.has_key(name) or DhcpFields.has_key(name):
			return True
		return False
		
	# Encode Packet and return it
	def EncodePacket(self):
		# MUST set options in order to respect the RFC (see router option)
		order = {}
		for each in self.options_data.keys():
			dhcp_each = DhcpOptions[each]
			order[dhcp_each] = option = []
			option.append(dhcp_each)
			
			options_each = self.options_data[each]
			option.append(len(options_each))
			option += options_each
			
		options = []
		for key in sorted(order.keys()):
			options += order[key]
			
		packet = self.packet_data[:240] + options
		packet.append(255) # add end option
		pack_fmt = str(len(packet)) + "c"
		packet = map(chr, packet)
		
		return pack(pack_fmt, *packet)
		
	# Insert packet in the object
	def DecodePacket(self, data, debug=False):
		if not data:
			return False
			
		# we transform all data to int list
		unpack_fmt = str(len(data)) + "c"
		self.packet_data = [ord(i) for i in unpack(unpack_fmt, data)]
		self.options_data = {}
		
		# Some servers or clients don't place magic cookie immediately
		# after headers and begin options fields only after magic.
		# These 4 lines search magic cookie and begin iterator after.
		iterator = 236
		end_iterator = len(self.packet_data)
		while not self.packet_data[iterator:iterator + 4] == MagicCookie and iterator < end_iterator:
			iterator += 1
		iterator += 4
		
		# parse extended options
		while iterator < end_iterator:
			if self.packet_data[iterator] == 0: # pad option
				opt_first = iterator + 1
				iterator += 1
			elif self.packet_data[iterator] == 255:
				self.packet_data = self.packet_data[:240] # base packet length without magic cookie
				return
			elif DhcpOptionsTypes.has_key(self.packet_data[iterator]) and not self.packet_data[iterator] == 255:
				opt_len = self.packet_data[iterator + 1]
				opt_first = iterator + 1
				self.options_data[DhcpOptionsList[self.packet_data[iterator]]] = self.packet_data[opt_first + 1:opt_len + opt_first + 1]
				iterator += self.packet_data[opt_first] + 2
			else:
				opt_first = iterator+1
				iterator += self.packet_data[opt_first] + 2
				
		# cut packet_data to remove options
		self.packet_data = self.packet_data[:240] # base packet length with magic cookie
		