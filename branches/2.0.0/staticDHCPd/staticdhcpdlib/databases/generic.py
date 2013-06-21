# -*- encoding: utf-8 -*-
"""
staticDHCPd module: databases.generic

Purpose
=======
 Provides a uniform datasource API, to be implemented by technology-specific
 backends.
 
Legal
=====
 This file is part of staticDHCPd.
 staticDHCPd is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program. If not, see <http://www.gnu.org/licenses/>.
 
 (C) Neil Tallim, 2013 <flan@uguu.ca>
"""
import collections
import logging

_logger = logging.getLogger('databases.generic')

Definition = collections.namedtuple('Definition', (
 'ip', 'hostname',
 'gateway', 'subnet_mask', 'broadcast_address',
 'domain_name', 'domain_name_servers', 'ntp_servers',
 'lease_time',
 'subnet', 'serial',
))
"""
`ip`: '192.168.0.1'
`hostname`: 'any-valid-hostname' or None
`gateway`: '192.168.0.1' or None
`subnet_mask`: '255.255.255.0' or None
`broadcast_address`: '192.168.0.255' or None
`domain_name`: 'example.org' or None
`domain_name_servers`: '192.168.0.1, 192.168.0.2,192.168.0.3' or None
`ntp_servers`: '192.168.0.1, 192.168.0.2,192.168.0.3' or None
`lease_time`: 3600
`subnet`: 'subnet-id`
`serial`: 0
"""

class Database(object):
    """
    A stub documenting the features a Database object must provide.
    """
    def lookupMAC(self, mac):
        """
        Queries the database for the given MAC address and returns the IP and
        associated details if the MAC is known.
        
        @type mac: basestring
        @param mac: The MAC address to lookup.
        
        @rtype: Definition|None
        @return: The definition or None, if no match was found.
        
        @raise Exception: If a problem occurs while accessing the database.
        """
        raise NotImplementedError("lookupMAC() must be implemented by subclasses")
        
    def reinitialise(self):
        """
        Though subclass-dependent, this will generally result in some guarantee
        that the database will provide fresh data, whether that means flushing
        a cache or reconnecting to the source.
        """
        