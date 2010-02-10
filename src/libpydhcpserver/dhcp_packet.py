# -*- encoding: utf-8 -*-
"""
libpydhcpserver module: dhcp_packet

Purpose
=======
 Extended class to offer convenience functions and processing for DHCP packets.
 
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
import operator
from struct import unpack
from struct import pack

from dhcp_constants import *
from type_hwmac import hwmac
from type_ipv4 import ipv4
from type_strlist import strlist
from type_rfc import *

class DHCPPacket(object):
	_packet_data = None
	_options_data = None
	_requested_options = None
	
	def __init__(self, data=None):
		self._options_data = {}
		if not data:
			self._packet_data = [0]*240
			self._packet_data[236:240] = MAGIC_COOKIE
			return
			
		# we transform all data to int list
		unpack_fmt = str(len(data)) + "c"
		self._packet_data = [ord(i) for i in unpack(unpack_fmt, data)]
		
		# Some servers or clients don't place magic cookie immediately
		# after headers and begin options fields only after magic.
		# These 4 lines search magic cookie and begin iterator after.
		iterator = 236
		end_iterator = len(self._packet_data)
		while not self._packet_data[iterator:iterator + 4] == MAGIC_COOKIE and iterator < end_iterator:
			iterator += 1
		iterator += 4
		
		# parse extended options
		while iterator < end_iterator:
			if self._packet_data[iterator] == 0: # pad option
				opt_first = iterator + 1
				iterator += 1
			elif self._packet_data[iterator] == 255:
				self._packet_data = self._packet_data[:240] # base packet length without magic cookie
				return
			elif DHCP_OPTIONS_TYPES.has_key(self._packet_data[iterator]) and not self._packet_data[iterator] == 255:
				opt_len = self._packet_data[iterator + 1]
				opt_first = iterator + 1
				opt_id = self._packet_data[iterator]
				opt_val = self._packet_data[opt_first + 1:opt_len + opt_first + 1]
				self._options_data[DHCP_OPTIONS_REVERSE[opt_id]] = opt_val
				if opt_id == 55:
					self._requested_options = tuple(set(
					 [int(i) for i in opt_val] + [1, 3, 6, 15, 51, 53, 54, 58, 59]
					))
				iterator += self._packet_data[opt_first] + 2
			else:
				opt_first = iterator+1
				iterator += self._packet_data[opt_first] + 2
				
		# cut packet_data to remove options
		self._packet_data = self._packet_data[:240] # base packet length with magic cookie
		
	def isDHCPPacket(self):
		return self._packet_data[236:240] == MAGIC_COOKIE
		
	def checkType(self, variable):
		# Check if variable is a list of ints between 0 and 255
		if not type(variable) == list:
			return False
		return bool([None for byte in variable if not type(byte) == int or not 0 <= byte <= 255])
		
	def deleteOption(self, name):
		#zero-out the value if it is core to the DHCP packet, else just drop it
		if DHCP_FIELDS.has_key(name):
			dhcp_field = DHCP_FIELDS[name]
			begin = dhcp_field[0]
			end = dhcp_field[0] + dhcp_field[1]
			self._packet_data[begin:end] = [0]*dhcp_field[1]
			return True
		else:
			if type(name) == int: #Translate int to string.
				name = DHCP_OPTIONS_REVERSE.get(name)
			if self._options_data.has_key(name):
				del self._options_data[name]
				return True
		return False
		
	def getOption(self, name):
		if DHCP_FIELDS.has_key(name):
			option_info = DHCP_FIELDS[name]
			return self._packet_data[option_info[0]:option_info[0] + option_info[1]]
		else:
			if type(name) == int: #Translate int to string.
				name = DHCP_OPTIONS_REVERSE.get(name)
			if self._options_data.has_key(name):
				return self._options_data[name]
		return None
		
	def _setRfcOption(self, name, value, expected_type):
		if type(value) == expected_type:
			self._options_data[name] = value.getValue()
			return True
		elif type(value) in (list, tuple):
			self._options_data[name] = list(value)
			return True
		return False
		
	def setOption(self, name, value):
		#Basic value checking: does the value list have a valid length?
		if DHCP_FIELDS.has_key(name):
			dhcp_field = DHCP_FIELDS[name]
			if not len(value) == dhcp_field[1]:
				return False 
			begin = dhcp_field[0]
			end = dhcp_field[0] + dhcp_field[1]
			self._packet_data[begin:end] = value
			return True
		else:
			if type(name) == int:
				name = DHCP_OPTIONS_REVERSE.get(name)
			dhcp_field_type = DHCP_OPTIONS_TYPES.get(DHCP_OPTIONS.get(name))
			if not dhcp_field_type:
				return False
				
			#Process normal options.
			dhcp_field_specs = DHCP_FIELDS_SPECS[dhcp_field_type]
			if dhcp_field_specs:
				(fixed_length, minimum_length, multiple) = dhcp_field_specs
				length = len(value)
				if fixed_length == length or (minimum_length <= length and length % multiple == 0):
					self._options_data[name] = value
					return True
				return False
			else:
				#Process special RFC options.
				if dhcp_field_type == 'RFC2610_78':
					return self._setRfcOption(name, value, rfc2610_78)
				elif dhcp_field_type == 'RFC2610_79':
					return self._setRfcOption(name, value, rfc2610_79)
				elif dhcp_field_type == 'RFC3361_120':
					return self._setRfcOption(name, value, rfc3361_120)
				elif dhcp_field_type == 'RFC3397_119':
					return self._setRfcOption(name, value, rfc3397_119)
				elif dhcp_field_type == 'RFC4174_83':
					return self._setRfcOption(name, value, rfc4174_83)
		raise ValueError("pydhcplib.dhcp_basic_packet.setoption error : unknown option: %(name)s" % {'name': name})
		
	def forceOption(self, option, value):
		name, id = None
		if type(option) == int: #Translate int to string.
			name = DHCP_OPTIONS_REVERSE.get(option)
			id = option
		else: #Translate string into int.
			id = DHCP_OPTIONS.get(option)
			name = option
			
		if name and id:
			if self._requested_options:
				self._requested_options += (option,)
			self._options_data[name] = value
		else:
			raise ValueError("pydhcplib.dhcp_basic_packet.forceoption error : unknown option: %(option)s" % {'option': option})
			
	def isOption(self, name):
		if type(name) == int: #Translate int to string.
			self._options_data.has_key(DHCP_OPTIONS_REVERSE.get(name))
		return self._options_data.has_key(name) or DHCP_FIELDS.has_key(name)
		
	def encodePacket(self):
		#MUST set options in ascending order to respect RFC2131 (see 'router')
		options = {}
		for key in self._options_data.keys():
			option_id = DHCP_OPTIONS[key]
			if self._requested_options is None or option_id in self._requested_options:
				option_value = self._options_data[key]
				
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
			
		packet = self._packet_data[:240] + ordered_options
		packet.append(255) # add end option
		pack_fmt = str(len(packet)) + "c"
		packet = map(chr, packet)
		
		return pack(pack_fmt, *packet)
		
	#Packet type resolution
	def isDHCPSomethingPacket(self, type):
		if not self.isDHCPPacket():
			return False
		if not self.isOption("dhcp_message_type"):
			return False
		if not self.getOption("dhcp_message_type") == type:
			return False
		return True
		
	def isDHCPDiscoverPacket(self):
		return self.isDHCPSomethingPacket([1])
		
	def isDHCPOfferPacket(self):
		return self.isDHCPSomethingPacket([2])
		
	def isDHCPRequestPacket(self):
		return self.isDHCPSomethingPacket([3])
		
	def isDHCPDeclinePacket(self):
		return self.isDHCPSomethingPacket([4])
		
	def isDHCPAckPacket(self):
		return self.isDHCPSomethingPacket([5])
		
	def isDHCPNackPacket(self):
		return self.isDHCPSomethingPacket([6])
		
	def isDHCPReleasePacket(self):
		return self.isDHCPSomethingPacket([7])
		
	def isDHCPInformPacket(self):
		return self.isDHCPSomethingPacket([8])
		
	def isDHCPLeaseQueryPacket(self):
		return self.isDHCPSomethingPacket([10])
		
	def isDHCPLeaseUnassignedPacket(self):
		return self.isDHCPSomethingPacket([11])
		
	def isDHCPLeaseUnknownPacket(self):
		return self.isDHCPSomethingPacket([12])
		
	def isDHCPLeaseActivePacket(self):
		return self.isDHCPSomethingPacket([13])
		
			
	#OFFER section
	def transformToDHCPOfferPacket(self):
		self.setOption("op", [2])
		self.setOption("hlen", [6])
		self.setOption("dhcp_message_type", [2])
		
		self.deleteOption("secs")
		self.deleteOption("ciaddr")
		self.deleteOption("request_ip_address")
		self.deleteOption("parameter_request_list")
		self.deleteOption("client_identifier")
		self.deleteOption("maximum_message_size")
		
	#ACK section
	def transformToDHCPAckPacket(self):
		self.setOption("op", [2])
		self.setOption("hlen", [6])
		self.setOption("dhcp_message_type", [5])
		
		self.deleteOption("secs")
		self.deleteOption("request_ip_address")
		self.deleteOption("parameter_request_list")
		self.deleteOption("client_identifier")
		self.deleteOption("maximum_message_size")
		
	#NAK section
	def transformToDHCPNackPacket(self):
		self.setOption("op", [2])
		self.setOption("hlen", [6])
		self.setOption("dhcp_message_type", [6])
		
		self.deleteOption("secs")
		self.deleteOption("ciaddr")
		self.deleteOption("yiaddr")
		self.deleteOption("siaddr")
		self.deleteOption("sname")
		self.deleteOption("file")
		self.deleteOption("request_ip_address")
		self.deleteOption("ip_address_lease_time_option")
		self.deleteOption("parameter_request_list")
		self.deleteOption("client_identifier")
		self.deleteOption("maximum_message_size")
		
	#LEASE section
	def transformToDHCPLeaseActivePacket(self):
		self.setOption("op", [2])
		self.setOption("hlen", [6])
		self.setOption("dhcp_message_type", [13])
		
		self.deleteOption("secs")
		self.deleteOption("ciaddr")
		self.deleteOption("request_ip_address")
		self.deleteOption("parameter_request_list")
		self.deleteOption("client_identifier")
		self.deleteOption("maximum_message_size")
		self.deleteOption("file")
		self.deleteOption("sname")
		
	def transformToDHCPLeaseUnknownPacket(self):
		self.setOption("op", [2])
		self.setOption("hlen", [6])
		self.setOption("dhcp_message_type", [12])
		
		self.deleteOption("secs")
		self.deleteOption("ciaddr")
		self.deleteOption("request_ip_address")
		self.deleteOption("parameter_request_list")
		self.deleteOption("client_identifier")
		self.deleteOption("maximum_message_size")
		self.deleteOption("file")
		self.deleteOption("sname")
		
	#ID section
	def getClientIdentifier(self):
		if self.isOption("client_identifier"):
			return self.getOption("client_identifier")
		return []
		
	def getGiaddr(self):
		return self.getOption("giaddr")
		
	def getHardwareAddress(self):
		length = self.getOption("hlen")[0]
		full_hw = self.getOption("chaddr")
		if length and length < len(full_hw):
			return full_hw[0:length]
		return full_hw
		
	#Python functions
	def __str__(self):
		"""
		Renders this packet's data in human-readable form.
		"""
		# Process headers
		output = ['#Header fields']
		op = self._packet_data[DHCP_FIELDS['op'][0]:DHCP_FIELDS['op'][0] + DHCP_FIELDS['op'][1]]
		output.append("op : %(type)s" % {'type': DHCP_FIELDS_NAME['op'][str(op[0])],})
		
		for opt in (
		 'htype','hlen','hops','xid','secs','flags',
		 'ciaddr','yiaddr','siaddr','giaddr','chaddr',
		 'sname','file',
		):
			begin = DHCP_FIELDS[opt][0]
			end = DHCP_FIELDS[opt][0] + DHCP_FIELDS[opt][1]
			data = self._packet_data[begin:end]
			result = None
			if DHCP_FIELDS_TYPES[opt] == "int":
				result = str(data[0])
			elif DHCP_FIELDS_TYPES[opt] == "int2":
				result = str(data[0] * 256 + data[1])
			elif DHCP_FIELDS_TYPES[opt] == "int4":
				result = str(ipv4(data).int())
			elif DHCP_FIELDS_TYPES[opt] == "str":
				result = []
				for each in data:
					if not each == 0:
						result.append(chr(each))
					else:
						break
				result = ''.join(result)
			elif DHCP_FIELDS_TYPES[opt] == "ipv4":
				result = ipv4(data).str()
			elif DHCP_FIELDS_TYPES[opt] == "hwmac":
				result = []
				hexsym = ('0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',)
				for iterator in xrange(6):
					result.append(str(hexsym[data[iterator] / 16] + hexsym[data[iterator] % 16]))
				result = ':'.join(result)
			output.append("%(opt)s : %(result)s" % {'opt': opt, 'result': result,})
			
		# Process options
		output.append("# Options fields")
		
		for opt in self._options_data.keys():
			data = self._options_data[opt]
			result = None
			optnum  = DHCP_OPTIONS[opt]
			if opt == 'dhcp_message_type':
				result = DHCP_FIELDS_NAMES['dhcp_message_type'][str(data[0])]
			elif DHCP_OPTIONS_TYPES[optnum] in ("char", "byte"):
				result = str(data[0])
			elif DHCP_OPTIONS_TYPES[optnum] == "16-bits":
				result = str(data[0] * 256 + data[0])
			elif DHCP_OPTIONS_TYPES[optnum] == "32-bits":
				result = str(ipv4(data).int())
			elif DHCP_OPTIONS_TYPES[optnum] == "string":
				result = []
				for each in data :
					if not each == 0:
						result.append(chr(each))
					else:
						break
				result = ''.join(result)
			elif DHCP_OPTIONS_TYPES[optnum] == "ipv4":
				result = ipv4(data).str()
			elif DHCP_OPTIONS_TYPES[optnum] == "ipv4+":
				result = []
				for i in xrange(0, len(data), 4):
					if len(data[i:i+4]) == 4:
						result.append(ipv4(data[i:i+4]).str())
				result = ' - '.join(result)
			elif DHCP_OPTIONS_TYPES[optnum] == "char+":
				if optnum == 55: # parameter_request_list
					requested_options = []
					for each in data:
						requested_options.append(DHCP_OPTIONS_REVERSE[int(each)])
					result = ', '.join(requested_options)
				else:
					result = str(data)
			elif DHCP_OPTIONS_TYPES[optnum] == "byte+":
				result = str(data)
			else:
				result = str(data)
			output.append("%(opt)s : %(result)s" % {'opt': opt, 'result': result,})
		return '\n'.join(output)
		
