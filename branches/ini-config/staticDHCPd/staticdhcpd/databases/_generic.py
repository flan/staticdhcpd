# -*- encoding: utf-8 -*-
"""
staticDHCPd module: databases._generic

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
import threading

from .. import config

class Database(object):
    """
    A stub documenting the features an _SQLBroker object must provide.
    """
    _resource_lock = None #: A lock used to prevent the database from being overwhelmed.
    _cache_lock = None #: A lock used to prevent multiple simultaneous cache updates.
    _mac_cache = None #: A cache used to prevent unnecessary database hits.
    _subnet_cache = None #: A cache used to prevent unnecessary database hits.
    
    def _getConnection(self):
        """
        Provides a connection to the database.

        @return: The connection object to be used.

        @raise Exception: If a problem occurs while accessing the database.
        """
        raise NotImplementedError("_getConnection must be overridden")
        
    def _setupBroker(self, concurrency_limit):
        """
        Sets up common attributes of broker objects.
        
        Must be invoked by subclasses' __init__() methods.
        
        @type concurrency_limit: int
        @param concurrent_limit: The number of concurrent database hits to
            permit.
        """
        self._resource_lock = threading.BoundedSemaphore(concurrency_limit)
        self._setupCache()
        
    def _setupCache(self):
        """
        Sets up the SQL broker cache.
        """
        if config.USE_CACHE:
            self._cache_lock = threading.Lock()
            self._mac_cache = {}
            self._subnet_cache = {}
            
    def flushCache(self):
        """
        Resets the cache to an empty state, forcing all lookups to pull fresh
        data.
        """
        if config.USE_CACHE:
            with self._cache_lock:
                self._mac_cache = {}
                self._subnet_cache = {}
                
    def lookupMAC(self, mac):
        """
        Queries the database for the given MAC address and returns the IP and
        associated details if the MAC is known.
        
        If enabled, the cache is checked and updated by this function.
        
        @type mac: basestring
        @param mac: The MAC address to lookup.
        
        @rtype: tuple(11)|None
        @return: (ip:basestring, hostname:basestring|None,
            gateway:basestring|None, subnet_mask:basestring|None,
            broadcast_address:basestring|None,
            domain_name:basestring|None, domain_name_servers:basestring|None,
            ntp_servers:basestring|None, lease_time:int,
            subnet:basestring, serial:int) or None if no match was
            found.
        
        @raise Exception: If a problem occurs while accessing the database.
        """
        if config.USE_CACHE:
            with self._cache_lock:
                data = self._mac_cache.get(mac)
                if data:
                    (ip, hostname, subnet_id) = data
                    return (ip, hostname,) + self._subnet_cache[subnet_id] + subnet_id
                    
        with self._resource_lock:
            data = self._lookupMAC(mac)
            if config.USE_CACHE:
                if data:
                    (ip, hostname,
                     gateway, subnet_mask, broadcast_address,
                     domain_name, domain_name_servers, ntp_servers,
                     lease_time, subnet, serial) = data
                    subnet_id = (subnet, serial)
                    with self._cache_lock:
                        self._mac_cache[mac] = (ip, hostname, subnet_id,)
                        self._subnet_cache[subnet_id] = (
                         gateway, subnet_mask, broadcast_address,
                         domain_name, domain_name_servers, ntp_servers,
                         lease_time,
                        )
            return data
