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
 
 (C) Neil Tallim, 2010 <red.hamsterx@gmail.com>
 (C) Mathieu Ignacio, 2008 <mignacio@april.org>
"""
MAGIC_COOKIE = [99,130,83,99] #: The DHCP magic cookie value, defined in RFC 1048.

DHCP_FIELDS_NAMES = {
 'op': {0: 'ERROR_UNDEF', 1: 'BOOTREQUEST', 2: 'BOOTREPLY',},
 'dhcp_message_type': {
  0: 'ERROR_UNDEF',
  1: 'DHCP_DISCOVER', 2: 'DHCP_OFFER',
  3: 'DHCP_REQUEST', 4:'DHCP_DECLINE',
  5: 'DHCP_ACK', 6: 'DHCP_NACK',
  7: 'DHCP_RELEASE',
  8: 'DHCP_INFORM',
  9: 'DHCP_FORCERENEW',
  10: 'DHCP_LEASEQUERY', 11: 'DHCP_LEASEUNASSIGNED',
  12: 'DHCP_LEASEUNKNOWN', 13: 'DHCP_LEASEACTIVE',
 }
} #: Mapping from DHCP option values to human-readable names.
DHCP_NAMES = {
 'ERROR_UNDEF': 0,
 'BOOTREQUEST': 1, 'BOOTREPLY': 2,
 'DHCP_DISCOVER': 1, 'DHCP_OFFER': 2,
 'DHCP_REQUEST': 3, 'DHCP_DECLINE': 4,
 'DHCP_ACK': 5, 'DHCP_NACK': 6,
 'DHCP_RELEASE': 7,
 'DHCP_INFORM': 8,
 'DHCP_FORCERENEW': 9,
 'DHCP_LEASEQUERY': 10, 'DHCP_LEASEUNASSIGNED': 11,
 'DHCP_LEASEUNKNOWN': 12, 'DHCP_LEASEACTIVE': 13,
} #: Mapping from human-readable names to DHCP option values.

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
} #: Maps from human-readable option field names their position within the fixed-size core packet body and the length of each field.

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
"""
Provides information about how to validate each basic DHCP option type.

The human-readable format-name is mapped against a
(fixed_length, minimum_length, multiple) tuple, which is handled by the
following algorithm:
    if C{fixed_length} == 0:
        C{minimum_length} and C{multiple} apply
        resulting length must be a multiple of C{multiple}
    else:
        only C{fixed_length} is considered
"""

DHCP_FIELDS_TYPES = {
 'op': "byte",
 'htype': "byte",
 'hlen': "byte",
 'hops': "byte",
 'xid': "32-bits",
 'secs': "16-bits",
 'flags': "16-bits",
 'ciaddr': "ipv4",
 'yiaddr': "ipv4",
 'siaddr': "ipv4",
 'giaddr': "ipv4",
 'chaddr': "hwmac",
 'sname': "string",
 'file': "string",
} #: Maps human-readable field-names to DHCP fields specs.

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
 88: "RFC4280_88", #Implemented
 89: "ipv4+",
 90: "RFC3118_90", #Not implemented; not necessary for static model
 91: "32-bits",
 92: "ipv4+",
 93: "16-bits",
 94: "byte+",
 95: "string", #Specifications not published
 96: "Unassigned",
 97: "byte+",
 98: "string",
 99: "byte+",
 100: "string",
 101: "string",
 102: "Unassigned", 103: "Unassigned", 104: "Unassigned", 105: "Unassigned",
 106: "Unassigned", 107: "Unassigned", 108: "Unassigned", 109: "Unassigned",
 110: "Unassigned", 111: "Unassigned",
 112: "string", #Specifications not published
 113: "string", #Specifications not published
 114: "string", #Specifications not published
 115: "Unassigned",
 116: "bool",
 117: "16-bits+",
 118: "ipv4",
 119: "RFC3397_119", #Implemented
 120: "RFC3361_120", #Implemented
 121: "byte+",
 122: "string",
 123: "byte+",
 124: "string",
 125: "string",
 126: "Unassigned", 127: "Unassigned",
 128: "string",
 129: "string",
 130: "string",
 131: "string",
 132: "string",
 133: "string",
 134: "string",
 135: "string",
 136: "ipv4+",
 137: "RFC5223_137", #Implemented
 138: "ipv4+",
 139: "RFC5678_139", #Implemented
 140: "RFC5678_140", #Implemented
 141: "Unassigned", 142: "Unassigned", 143: "Unassigned", 144: "Unassigned",
 145: "Unassigned", 146: "Unassigned", 147: "Unassigned", 148: "Unassigned",
 149: "Unassigned",
 150: "Unassigned", #TFTP server address
 151: "Unassigned", 152: "Unassigned", 153: "Unassigned", 154: "Unassigned",
 155: "Unassigned", 156: "Unassigned", 157: "Unassigned", 158: "Unassigned",
 159: "Unassigned", 160: "Unassigned", 161: "Unassigned", 162: "Unassigned",
 163: "Unassigned", 164: "Unassigned", 165: "Unassigned", 166: "Unassigned",
 167: "Unassigned", 168: "Unassigned", 169: "Unassigned", 170: "Unassigned",
 171: "Unassigned", 172: "Unassigned", 173: "Unassigned", 174: "Unassigned",
 175: "Unassigned", #Etherboot
 176: "Unassigned", #IP Telephone
 177: "Unassigned", #Etherboot
 178: "Unassigned", 179: "Unassigned", 180: "Unassigned", 181: "Unassigned",
 182: "Unassigned", 183: "Unassigned", 184: "Unassigned", 185: "Unassigned",
 186: "Unassigned", 187: "Unassigned", 188: "Unassigned", 189: "Unassigned",
 190: "Unassigned", 191: "Unassigned", 192: "Unassigned", 193: "Unassigned",
 194: "Unassigned", 195: "Unassigned", 196: "Unassigned", 197: "Unassigned",
 198: "Unassigned", 199: "Unassigned", 200: "Unassigned", 201: "Unassigned",
 202: "Unassigned", 203: "Unassigned", 204: "Unassigned", 205: "Unassigned",
 206: "Unassigned", 207: "Unassigned",
 208: "32-bits",
 209: "string",
 210: "string",
 211: "32-bits",
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
"""
Maps DHCP option-numbers to DHCP fields specs.

All values derived from http://www.iana.org/assignments/bootp-dhcp-parameters
"""

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
 'bcmcs_domain_list': 88,
 'bcmcs_ipv4_list': 89,
 'authentication': 90,
 'client_last_transaction_time': 91,
 'associated_ip': 92,
 'client_system': 93,
 'client_ndi': 94,
 'ldap': 95,
 #Hole
 'uuid_guid': 97,
 'open_group_user_auth': 98,
 'geoconf_civic': 99,
 'pcode': 100,
 'tcode': 101,
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
 'pxe_128': 128,
 'pxe_129': 129,
 'pxe_130': 130,
 'pxe_131': 131,
 'pxe_132': 132,
 'pxe_133': 133,
 'pxe_134': 134,
 'pxe_135': 135,
 'pana_agent': 136,
 'v4_lost': 137,
 'capwap_ac_v4': 138,
 'ipv4_mos': 139,
 'fqdn_mos': 140,
 #Hole.
 'pxelinux_magic': 208,
 'configuration_file': 209,
 'path_prefix': 210,
 'reboot_time': 211,
 #Hole.
 'end': 255
} #: Maps human-readable DHCP option names to integer values.

DHCP_OPTIONS_REVERSE = dict([(v, k) for (k, v) in DHCP_OPTIONS.iteritems()]) #: Maps integer values to human-readable DHCP option names.
