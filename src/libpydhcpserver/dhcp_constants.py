# -*- encoding: utf-8 -*-
"""
libpydhcpserver module: dhcp_constants

Purpose
=======
 Contains constants needed by libpydhcpserver.
 
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
MAGIC_COOKIE = [99,130,83,99]
VERSION = '0.9.9'

# DhcpBaseOptions = {'fieldname': (location, length),}
DHCP_FIELDS = {
 'op': (0, 1),
 'htype': (1, 1),
 'hlen': (2, 1),
 'hops': (3, 1),
 'xid': (4, 4),
 'secs': (8, 2),
 'flags': (10, 2),
 'ciaddr': (12, 4),
 'yiaddr': (16, 4),
 'siaddr': (20, 4),
 'giaddr': (24, 4),
 'chaddr': (28, 6),
 'sname': (44, 64),
 'file': (108, 128),
}
DHCP_FIELDS_NAMES = {
 'op': {'0': 'ERROR_UNDEF', '1': 'BOOTREQUEST', '2': 'BOOTREPLY',},
 'dhcp_message_type': {
  '0': 'ERROR_UNDEF',
  '1': 'DHCP_DISCOVER', '2': 'DHCP_OFFER',
  '3': 'DHCP_REQUEST', '4':'DHCP_DECLINE',
  '5': 'DHCP_ACK', '6': 'DHCP_NACK',
  '7': 'DHCP_RELEASE', '8': 'DHCP_INFORM',
  '10': 'DHCP_LEASEQUERY', '11': 'DHCP_LEASEUNASSIGNED',
  '12': 'DHCP_LEASEUNKNOWN', '13': 'DHCP_LEASEACTIVE',
 }
}
DHCP_NAMES = {
 'ERROR_UNDEF': 0,
 'BOOTREQUEST': 1, 'BOOTREPLY': 2,
 'DHCP_DISCOVER': 1, 'DHCP_OFFER': 2,
 'DHCP_REQUEST': 3, 'DHCP_DECLINE': 4,
 'DHCP_ACK': 5, 'DHCP_NACK': 6,
 'DHCP_RELEASE': 7, 'DHCP_INFORM': 8,
 'DHCP_LEASEQUERY': 10, 'DHCP_LEASEUNASSIGNED': 11,
 'DHCP_LEASEUNKNOWN': 12, 'DHCP_LEASEACTIVE': 13,
}
DHCP_FIELDS_TYPES = {
 'op': "int",
 'htype': "int",
 'hlen': "int",
 'hops': "int",
 'xid': "int4",
 'secs': "int2",
 'flags': "int2",
 'ciaddr': "ipv4",
 'yiaddr': "ipv4",
 'siaddr': "ipv4",
 'giaddr': "ipv4",
 'chaddr': "hwmac",
 'sname': "str",
 'file': "str",
}
DHCP_FIELDS_SPECS = {
 "ipv4": (4, 0, 1), "ipv4+": (0, 4, 4), "ipv4*": (0, 0, 4),
 "byte": (1, 0, 1), "byte+": (0, 1, 1),
 "char": (1, 0, 1), "char+": (0, 1, 1),
 "string": (0, 0, 1),
 "bool": (1, 0, 1),
 "16-bits": (2, 0, 1), "16-bits+": (0, 2, 2),
 "32-bits": (4, 0, 1), "32-bits+": (0, 4, 4),
 "identifier": (0, 2, 1),
 "none": (0, 0, 1),
}
# DHCP_FIELDS_SPECS : {'option_code': (fixed_length, minimum_length, multiple)}
# if fixed_length == 0 : minimum_length and multiple apply
# else : forget minimum_length and multiple 
# multiple : length MUST be a multiple of 'multiple'

# DHCP_OPTIONS = {'option_name': option_code,}
DHCP_OPTIONS = {
 'pad': 0,
 # Vendor Extension
 'subnet_mask': 1,
 'time_offset': 2,
 'router': 3,
 'time_server': 4,
 'name_server': 5,
 'domain_name_servers': 6,
 'log_server': 7,
 'cookie_server': 8,
 'lpr_server': 9,
 'impress_server': 10,
 'resource_location_server': 11,
 'hostname': 12,
 'bootfile': 13,
 'merit_dump_file': 14,
 'domain_name': 15,
 'swap_server': 16,
 'root_path': 17,
 'extensions_path': 18,
 # IP layer parameters per host
 'ip_forwarding': 19,
 'nonlocal_source_routing': 20,
 'policy_filter': 21,
 'maximum_datagram_reassembly_size': 22,
 'default_ip_time-to-live': 23,
 'path_mtu_aging_timeout': 24,
 'path_mtu_table': 25,
 # IP layer parameters per interface
 'interface_mtu': 26,
 'all_subnets_are_local': 27,
 'broadcast_address': 28,
 'perform_mask_discovery': 29,
 'mask_supplier': 30,
 'perform_router_discovery': 31,
 'router_solicitation_address': 32,
 'static_routes': 33,
 # link layer parameters per interface
 'trailer_encapsulation': 34,
 'arp_cache_timeout': 35,
 'ethernet_encapsulation': 36,
 # TCP parameters
 'tcp_default_ttl': 37,
 'tcp_keepalive_interval': 38,
 'tcp_keepalive_garbage': 39,
 # Applications and service parameters
 'nis_domain': 40,
 'nis_servers': 41,
 'ntp_servers': 42,
 'vendor_specific_information': 43,
 'nbns': 44,
 'nbdd': 45,'nb_node_type': 46,
 'nb_scope': 47,
 'x_window_system_font_server': 48,
 'x_window_system_display_manager': 49,
 # DHCP extensions
 'requested_ip_address': 50,
 'ip_address_lease_time': 51,
 'overload': 52,
 'dhcp_message_type': 53,
 'server_identifier': 54,
 'parameter_request_list': 55,
 'message': 56,
 'maximum_dhcp_message_size': 57,
 'renewal_time_value': 58,
 'rebinding_time_value': 59,
 'vendor_class_identifier': 60,
 'client_identifier': 61,
 # Add from RFC 2132
 'netware_ip_domain_name': 62,
 'netware_ip_sub_options': 63,
 'nis+_domain': 64,
 'nis+_servers': 65,
 'tftp_server_name': 66,
 'bootfile_name': 67,
 'mobile_ip_home_agent': 68,
 'smtp_servers': 69,
 'pop_servers': 70,
 'nntp_servers': 71,
 'default_www_server': 72,
 'default_finger_server': 73,
 'default_irc_server': 74,
 'streettalk_server': 75,
 'streettalk_directory_assistance_server': 76,
 'user_class': 77,
 'directory_agent': 78,
 'service_scope': 79,
 'rapid_commit': 80,
 'client_fqdn': 81,
 'relay_agent': 82,
 'internet_storage_name_service': 83,
 #Hole.
 'nds_server': 85,
 'nds_tree_name': 86,
 'nds_context': 87,
 #Hole.
 'authentication': 90,
 'client_last_transaction_time': 91,
 'associated_ip': 92,
 'client_system': 93,
 'client_ndi': 94,
 'ldap': 95,
 #Hole
 'uuid_guid': 97,
 'open_group_user_auth': 98,
 #Hole.
 'netinfo_address': 112,
 'netinfo_tag': 113,
 'url': 114,
 #Hole.
 'auto_config': 116,
 'name_service_search': 117,
 'subnet_selection': 118,
 'domain_search': 119,
 'sip_servers': 120,
 'classless_static_route': 121,
 'cablelabs_client_configuration': 122,
 'geoconf': 123,
 'vendor_class': 124,
 'vendor_specific': 125,
 #Hole.
 'end': 255
}
	
# DHCP_OPTIONS_REVERSE : reverse of DHCP_OPTIONS
DHCP_OPTIONS_REVERSE = dict([(v, k) for (k, v) in DHCP_OPTIONS.iteritems()])

# Derived from http://www.iana.org/assignments/bootp-dhcp-parameters
DHCP_OPTIONS_TYPES = {
 0: "none",
 1: "ipv4",
 2: "32-bits",
 3: "ipv4+",
 4: "ipv4+",
 5: "ipv4+",
 6: "ipv4+",
 7: "ipv4+",
 8: "ipv4+",
 9: "ipv4+",
 10: "ipv4+",
 11: "ipv4+",
 12: "string",
 13: "16-bits",
 14: "string",
 15: "string",
 16: "ipv4",
 17: "string",
 18: "string",
 19: "bool",
 20: "bool",
 21: "ipv4+",
 22: "16-bits",
 23: "byte",
 24: "32-bits",
 25: "16-bits+",
 26: "16-bits",
 27: "bool",
 28: "ipv4",
 29: "bool",
 30: "bool",
 31: "bool",
 32: "ipv4",
 33: "ipv4+",
 34: "bool",
 35: "32-bits",
 36: "bool",
 37: "byte",
 38: "32-bits",
 39: "bool",
 40: "string",
 41: "ipv4+",
 42: "ipv4+",
 43: "byte+",
 44: "ipv4+",
 45: "ipv4+",
 46: "byte",
 47: "string",
 48: "ipv4+",
 49: "ipv4+",
 50: "ipv4",
 51: "32-bits",
 52: "byte",
 53: "byte",
 54: "ipv4",
 55: "byte+",
 56: "string",
 57: "16-bits",
 58: "32-bits",
 59: "32-bits",
 60: "string",
 61: "identifier",
 62: "string",
 63: "byte+",
 64: "string",
 65: "ipv4+",
 66: "string",
 67: "string",
 68: "ipv4*",
 69: "ipv4+",
 70: "ipv4+",
 71: "ipv4+",
 72: "ipv4+",
 73: "ipv4+",
 74: "ipv4+",
 75: "ipv4+",
 76: "ipv4+",
 77: "RFC3004_77", #Not implemented; not necessary for static model
 78: "RFC2610_78", #Implemented
 79: "RFC2610_79", #Implemented
 80: "none",
 81: "string",
 82: "byte+",
 83: "RFC4174_83", #Implemented
 84: "Unassigned",
 85: "ipv4+",
 86: "byte+",
 87: "byte+",
 88: "Unassigned", 89: "Unassigned", #FIXME
 90: "RFC3118_90", #Not implemented; not necessary for static model
 91: "32-bits",
 92: "ipv4+",
 93: "Unassigned", 94: "Unassigned", 95: "Unassigned", #FIXME
 96: "Unassigned",
 97: "Unassigned", #FIXME
 98: "string",
 99: "Unassigned", 100: "Unassigned", 101: "Unassigned", #FIXME
 102: "Unassigned", 103: "Unassigned", 104: "Unassigned", 105: "Unassigned",
 106: "Unassigned", 107: "Unassigned", 108: "Unassigned", 109: "Unassigned",
 110: "Unassigned", 111: "Unassigned",
 112: "Unassigned", 113: "Unassigned", 114: "Unassigned", #FIXME
 115: "Unassigned",
 116: "bool",
 117: "16-bits+",
 118: "ipv4",
 119: "RFC3397_119", #Implemented
 120: "RFC3361_120", #Implemented
 #TODO
 121: "Unassigned", 122: "Unassigned", 123: "Unassigned", 124: "Unassigned",
 125: "Unassigned", 126: "Unassigned", 127: "Unassigned", 128: "Unassigned",
 129: "Unassigned", 130: "Unassigned", 131: "Unassigned", 132: "Unassigned",
 133: "Unassigned", 134: "Unassigned", 135: "Unassigned", 136: "Unassigned",
 137: "Unassigned", 138: "Unassigned", 139: "Unassigned", 140: "Unassigned",
 141: "Unassigned", 142: "Unassigned", 143: "Unassigned", 144: "Unassigned",
 145: "Unassigned", 146: "Unassigned", 147: "Unassigned", 148: "Unassigned",
 149: "Unassigned", 150: "Unassigned", 151: "Unassigned", 152: "Unassigned",
 153: "Unassigned", 154: "Unassigned", 155: "Unassigned", 156: "Unassigned",
 157: "Unassigned", 158: "Unassigned", 159: "Unassigned", 160: "Unassigned",
 161: "Unassigned", 162: "Unassigned", 163: "Unassigned", 164: "Unassigned",
 165: "Unassigned", 166: "Unassigned", 167: "Unassigned", 168: "Unassigned",
 169: "Unassigned", 170: "Unassigned", 171: "Unassigned", 172: "Unassigned",
 173: "Unassigned", 174: "Unassigned", 175: "Unassigned", 176: "Unassigned",
 177: "Unassigned", 178: "Unassigned", 179: "Unassigned", 180: "Unassigned",
 181: "Unassigned", 182: "Unassigned", 183: "Unassigned", 184: "Unassigned",
 185: "Unassigned", 186: "Unassigned", 187: "Unassigned", 188: "Unassigned",
 189: "Unassigned", 190: "Unassigned", 191: "Unassigned", 192: "Unassigned",
 193: "Unassigned", 194: "Unassigned", 195: "Unassigned", 196: "Unassigned",
 197: "Unassigned", 198: "Unassigned", 199: "Unassigned", 200: "Unassigned",
 201: "Unassigned", 202: "Unassigned", 203: "Unassigned", 204: "Unassigned",
 205: "Unassigned", 206: "Unassigned", 207: "Unassigned", 208: "Unassigned",
 209: "Unassigned", 210: "Unassigned", 211: "Unassigned",
 212: "Unassigned", 213: "Unassigned", 214: "Unassigned", 215: "Unassigned",
 216: "Unassigned", 217: "Unassigned", 218: "Unassigned", 219: "Unassigned",
 220: "Unassigned", #Subnet Allocation Option
 221: "Unassigned", #Virtual Subnet Selection Option
 222: "Unassigned", 223: "Unassigned",
 224: "Reserved", 225: "Reserved", 226: "Reserved", 227: "Reserved",
 228: "Reserved", 229: "Reserved", 230: "Reserved", 231: "Reserved",
 232: "Reserved", 233: "Reserved", 234: "Reserved", 235: "Reserved",
 236: "Reserved", 237: "Reserved", 238: "Reserved", 239: "Reserved",
 240: "Reserved", 241: "Reserved", 242: "Reserved", 243: "Reserved",
 244: "Reserved", 245: "Reserved", 246: "Reserved", 247: "Reserved",
 248: "Reserved", 249: "Reserved", 250: "Reserved", 251: "Reserved",
 252: "Reserved", 253: "Reserved", 254: "Reserved",
 255: "none",
}
