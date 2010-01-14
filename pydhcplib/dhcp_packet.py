# -*- encoding: utf-8 -*-
"""
pydhcplib module: dhcp_packet

Purpose
=======
 Extended class to offer convenience functions and processing for DHCP packets.
 
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
"""
import operator
from struct import unpack
from struct import pack

from dhcp_basic_packet import *
from dhcp_constants import *
from type_hwmac import hwmac
from type_ipv4 import ipv4
from type_strlist import strlist

class DhcpPacket(DhcpBasicPacket):
	#Packet type resolution
	def IsDhcpSomethingPacket(self, type):
		if not self.IsDhcpPacket():
			return False
		if not self.IsOption("dhcp_message_type"):
			return False
		if not self.GetOption("dhcp_message_type") == type:
			return False
		return True
		
	def IsDhcpDiscoverPacket(self):
		return self.IsDhcpSomethingPacket([1])
		
	def IsDhcpOfferPacket(self):
		return self.IsDhcpSomethingPacket([2])
		
	def IsDhcpRequestPacket(self):
		return self.IsDhcpSomethingPacket([3])
		
	def IsDhcpDeclinePacket(self):
		return self.IsDhcpSomethingPacket([4])
		
	def IsDhcpAckPacket(self):
		return self.IsDhcpSomethingPacket([5])
		
	def IsDhcpNackPacket(self):
		return self.IsDhcpSomethingPacket([6])
		
	def IsDhcpReleasePacket(self):
		return self.IsDhcpSomethingPacket([7])
		
	def IsDhcpInformPacket(self):
		return self.IsDhcpSomethingPacket([8])
		
	#OFFER section
	def CreateDhcpOfferPacketFrom(self, src): # src = discover packet
		self.requested_options = src.requested_options
		self.SetOption("htype", src.GetOption("htype"))
		self.SetOption("xid", src.GetOption("xid"))
		self.SetOption("flags", src.GetOption("flags"))
		self.SetOption("giaddr", src.GetOption("giaddr"))
		self.SetOption("chaddr", src.GetOption("chaddr"))
		self.SetOption("ip_address_lease_time", src.GetOption("ip_address_lease_time"))
		self.TransformToDhcpOfferPacket()
		
	def TransformToDhcpOfferPacket(self):
		self.SetOption("dhcp_message_type", [2])
		self.SetOption("op", [2])
		self.SetOption("hlen", [6])
		
		self.DeleteOption("secs")
		self.DeleteOption("ciaddr")
		self.DeleteOption("request_ip_address")
		self.DeleteOption("parameter_request_list")
		self.DeleteOption("client_identifier")
		self.DeleteOption("maximum_message_size")
		
	#ACK section
	def CreateDhcpAckPacketFrom(self, src): # src = request or inform packet
		self.requested_options = src.requested_options
		self.SetOption("htype", src.GetOption("htype"))
		self.SetOption("xid", src.GetOption("xid"))
		self.SetOption("ciaddr", src.GetOption("ciaddr"))
		self.SetOption("flags", src.GetOption("flags"))
		self.SetOption("giaddr", src.GetOption("giaddr"))
		self.SetOption("chaddr", src.GetOption("chaddr"))
		self.SetOption("ip_address_lease_time_option", src.GetOption("ip_address_lease_time_option"))
		self.TransformToDhcpAckPacket()
		
	def TransformToDhcpAckPacket(self): # src = request or inform packet
		self.SetOption("op", [2])
		self.SetOption("hlen", [6]) 
		self.SetOption("dhcp_message_type", [5])
		
		self.DeleteOption("secs")
		self.DeleteOption("request_ip_address")
		self.DeleteOption("parameter_request_list")
		self.DeleteOption("client_identifier")
		self.DeleteOption("maximum_message_size")
		
	#NAK section
	def CreateDhcpNackPacketFrom(self, src): # src = request or inform packet
		self.requested_options = src.requested_options
		self.SetOption("htype", src.GetOption("htype"))
		self.SetOption("xid", src.GetOption("xid"))
		self.SetOption("flags", src.GetOption("flags"))
		self.SetOption("giaddr", src.GetOption("giaddr"))
		self.SetOption("chaddr", src.GetOption("chaddr"))
		self.TransformToDhcpNackPacket()
		
	def TransformToDhcpNackPacket(self):
		self.SetOption("op", [2])
		self.SetOption("hlen", [6]) 
		self.DeleteOption("secs")
		self.DeleteOption("ciaddr")
		self.DeleteOption("yiaddr")
		self.DeleteOption("siaddr")
		self.DeleteOption("sname")
		self.DeleteOption("file")
		self.DeleteOption("request_ip_address")
		self.DeleteOption("ip_address_lease_time_option")
		self.DeleteOption("parameter_request_list")
		self.DeleteOption("client_identifier")
		self.DeleteOption("maximum_message_size")
		self.SetOption("dhcp_message_type", [6])
		
	#ID section
	def GetClientIdentifier(self):
		if self.IsOption("client_identifier"):
			return self.GetOption("client_identifier")
		return []
		
	def GetGiaddr(self):
		return self.GetOption("giaddr")
		
	def GetHardwareAddress(self):
		length = self.GetOption("hlen")[0]
		full_hw = self.GetOption("chaddr")
		if length and length < len(full_hw):
			return full_hw[0:length]
		return full_hw
		
	#Python functions
	def __str__(self):
		"""
		Renders this packet's data in human-readable form.
		"""
		# Process headers
		printable_data = "# Header fields\n"
		op = self.packet_data[DhcpFields['op'][0]:DhcpFields['op'][0] + DhcpFields['op'][1]]
		printable_data += "op : %(type)s\n" % {'type': DhcpFieldsName['op'][str(op[0])],}
		
		for opt in (
		 'htype','hlen','hops','xid','secs','flags',
		 'ciaddr','yiaddr','siaddr','giaddr','chaddr',
		 'sname','file',
		):
			begin = DhcpFields[opt][0]
			end = DhcpFields[opt][0] + DhcpFields[opt][1]
			data = self.packet_data[begin:end]
			result = ''
			if DhcpFieldsTypes[opt] == "int":
				result = str(data[0])
			elif DhcpFieldsTypes[opt] == "int2":
				result = str(data[0] * 256 + data[1])
			elif DhcpFieldsTypes[opt] == "int4":
				result = str(ipv4(data).int())
			elif DhcpFieldsTypes[opt] == "str":
				for each in data:
					if not each == 0:
						result += chr(each)
					else:
						break
			elif DhcpFieldsTypes[opt] == "ipv4":
				result = ipv4(data).str()
			elif DhcpFieldsTypes[opt] == "hwmac":
				result = []
				hexsym = ('0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',)
				for iterator in xrange(6):
					result.append(str(hexsym[data[iterator] / 16] + hexsym[data[iterator] % 16]))
				result = ':'.join(result)
			printable_data += "%(opt)s : %(result)s\n" % {'opt': opt, 'result': result,}
			
		# Process options
		printable_data += "# Options fields\n"
		
		for opt in self.options_data.keys():
			data = self.options_data[opt]
			result = ""
			optnum  = DhcpOptions[opt]
			if opt == 'dhcp_message_type':
				result = DhcpFieldsName['dhcp_message_type'][str(data[0])]
			elif DhcpOptionsTypes[optnum] == "char":
				result = str(data[0])
			elif DhcpOptionsTypes[optnum] == "16-bits":
				result = str(data[0] * 256 + data[0])
			elif DhcpOptionsTypes[optnum] == "32-bits":
				result = str(ipv4(data).int())
			elif DhcpOptionsTypes[optnum] == "string":
				for each in data :
					if not each == 0:
						result += chr(each)
					else:
						break
			elif DhcpOptionsTypes[optnum] == "ipv4":
				result = ipv4(data).str()
			elif DhcpOptionsTypes[optnum] == "ipv4+":
				for i in xrange(0, len(data), 4):
					if len(data[i:i+4]) == 4:
						result += ipv4(data[i:i+4]).str() + " - "
			elif DhcpOptionsTypes[optnum] == "char+":
				if optnum == 55: # parameter_request_list
					requested_options = []
					for each in data:
						requested_options.append(DhcpOptionsList[int(each)])
					result = ','.join(requested_options)
				else:
					result += str(data)
			printable_data += "%(opt)s : %(result)s\n" % {'opt': opt, 'result': result,}
		return printable_data
		
