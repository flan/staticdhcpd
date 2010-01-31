# -*- encoding: utf-8 -*-
"""
pydhcplib module: dhcp_basic_packet

Purpose
=======
 Base class to encode/decode dhcp packets.
 
Legal
=====
 This file is part of pydhcplib, but it has been altered for use with
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
 
 (C) Mathieu Ignacio, 2008 <mignacio@april.org>
 (C) Neil Tallim, 2009 <flan@uguu.ca>
"""
import operator
from struct import unpack
from struct import pack

from dhcp_constants import *
import type_rfc

class DhcpBasicPacket(object):
	def __init__(self):
		self.packet_data = [0]*240
		self.options_data = {}
		self.packet_data[236:240] = MagicCookie
		self.source_address = False
		self.requested_options = None
		
	def IsDhcpPacket(self):
		return self.packet_data[236:240] == MagicCookie
		
	def CheckType(self, variable):
		# Check if variable is a list of ints between 0 and 255
		if type(variable) == list:
			for each in variable:
				if not type(each) == int or not 0 <= each <= 255:
					return False
			return True
		return False
		
	def DeleteOption(self, name):
		#zero-out the value if it is core to the DHCP packet, else just drop it
		if DhcpFields.has_key(name):
			dhcp_field = DhcpFields[name]
			begin = dhcp_field[0]
			end = dhcp_field[0] + dhcp_field[1]
			self.packet_data[begin:end] = [0]*dhcp_field[1]
			return True
		else:
			if type(name) == int: #Translate int to string.
				name = DhcpOptionsList.get(name)
			if self.options_data.has_key(name):
				del self.options_data[name]
				return True
		return False
		
	def GetOption(self, name):
		if DhcpFields.has_key(name):
			option_info = DhcpFields[name]
			return self.packet_data[option_info[0]:option_info[0] + option_info[1]]
		else:
			if type(name) == int: #Translate int to string.
				name = DhcpOptionsList.get(name)
			if self.options_data.has_key(name):
				return self.options_data[name]
		return []
		
	def SetOption(self, name, value):
		#Basic value checking: does the value list have a valid length?
		if DhcpFields.has_key(name):
			dhcp_field = DhcpFields[name]
			if not len(value) == dhcp_field[1]:
				return False 
			begin = dhcp_field[0]
			end = dhcp_field[0] + dhcp_field[1]
			self.packet_data[begin:end] = value
			return True
		else:
			if type(name) == int:
				name = DhcpOptionsList.get(name)
			if not DhcpOptions.has_key(name):
				return False
				
			if dhcp_field_type == 'RFC2610_78':
				if type(value) == type_rfc.rfc2610_78:
					self.options_data[name] = value.getValue()
					return True
				return False
			elif dhcp_field_type == 'RFC2610_79':
				if type(value) == type_rfc.rfc2610_79:
					self.options_data[name] = value.getValue()
					return True
				return False
			elif dhcp_field_type == 'RFC3361_120':
				if type(value) == type_rfc.rfc3361_120:
					self.options_data[name] = value.getValue()
					return True
				return False
			elif dhcp_field_type == 'RFC3397_119':
				if type(value) == type_rfc.rfc3397_119:
					self.options_data[name] = value.getValue()
					return True
				return False
			elif dhcp_field_type == 'RFC4174_83':
				if type(value) == type_rfc.rfc4174_83:
					self.options_data[name] = value.getValue()
					return True
				return False
				
			(fixed_length, minimum_length, multiple) = DhcpFieldsSpecs[DhcpOptionsTypes[DhcpOptions[name]]]
			length = len(value)
			if fixed_length == length or (minimum_length <= length and length % multiple == 0):
				if type(name) == int: #Use the string name to avoid collisions.
					name = DhcpOptionsList.get(name)
					if not name:
						return False
				self.options_data[name] = value
				return True
			return False
		raise ValueError("pydhcplib.dhcp_basic_packet.setoption error : unknown option: %(name)s" % {'name': name})
		
	def IsOption(self, name):
		if type(name) == int: #Translate int to string.
			self.options_data.has_key(DhcpOptionsList.get(name))
		else:
			return self.options_data.has_key(name) or DhcpFields.has_key(name)
			
	def EncodePacket(self):
		#MUST set options in ascending order to respect RFC2131 (see 'router')
		options = {}
		for each in self.options_data.keys():
			option_id = DhcpOptions[each]
			if self.requested_options is None or option_id in self.requested_options:
				option_value = self.options_data[each]
				
				options[option_id] = option = []
				
				while True:
					if len(option_value) > 255:
						option += [option_id, 255] + option_value[:255]
						option_value = option_value[255:]
					else:
						option += [option_id, len(option_value)] + option_value
						break
		ordered_options = []
		for (option_id, value) in sorted(options.iteritems()):
			ordered_options += value
			
		packet = self.packet_data[:240] + ordered_options
		packet.append(255) # add end option
		pack_fmt = str(len(packet)) + "c"
		packet = map(chr, packet)
		
		return pack(pack_fmt, *packet)
		
	def DecodePacket(self, data):
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
				opt_id = self.packet_data[iterator]
				opt_val = self.packet_data[opt_first + 1:opt_len + opt_first + 1]
				self.options_data[DhcpOptionsList[opt_id]] = opt_val
				if opt_id == 55:
					self.requested_options = tuple(set(
					 [int(i) for i in opt_val] + [1, 3, 6, 15, 51, 53, 54, 58, 59]
					))
				iterator += self.packet_data[opt_first] + 2
			else:
				opt_first = iterator+1
				iterator += self.packet_data[opt_first] + 2
				
		# cut packet_data to remove options
		self.packet_data = self.packet_data[:240] # base packet length with magic cookie
		
