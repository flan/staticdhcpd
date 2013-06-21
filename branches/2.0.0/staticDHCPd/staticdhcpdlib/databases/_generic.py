# -*- encoding: utf-8 -*-
"""
staticDHCPd module: databases._generic

Purpose
=======
 Provides common templates for databases.
 
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
import logging
import threading

from .. import config

from generic import (Database, Definition)

_logger = logging.getLogger('databases._generic')

class CachingDatabase(Database):
    """
    A partial implementation of the Database engine, adding generic caching
    logic and concurrency-throttling.
    """
    _resource_lock = None #: A lock used to prevent the database from being overwhelmed.
    _cache_lock = None #: A lock used to prevent multiple simultaneous cache updates.
    _mac_cache = None #: A cache used to prevent unnecessary database hits.
    _subnet_cache = None #: A cache used to prevent unnecessary database hits.
    
    def __init__(self, concurrency_limit=2147483647):
        """
        Sets up common attributes of broker objects.
        
        Must be invoked by subclasses' __init__() methods.
        
        @type concurrency_limit: int
        @param concurrent_limit: The number of concurrent database hits to
            permit, defaulting to a ridiculously large number.
        """
        _logger.debug("Initialising database with a maximum of %(count)i concurrent connections" % {'count': concurrency_limit,})
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
            _logger.debug("Database cache initialised")
            
    def reinitialise(self):
        if config.USE_CACHE:
            with self._cache_lock:
                self._mac_cache.clear()
                self._subnet_cache.clear()
            _logger.info("Database cache cleared")
            
    def lookupMAC(self, mac):
        mac = str(mac)
        if config.USE_CACHE:
            with self._cache_lock:
                data = self._mac_cache.get(mac)
            if data:
                (ip, hostname, subnet_id) = data
                return Definition(*((ip, hostname,) + self._subnet_cache[subnet_id] + subnet_id))
                
        with self._resource_lock:
            definition = self._lookupMAC(mac)
            if definition and config.USE_CACHE:
                subnet_id = (definition.subnet, definition.serial)
                with self._cache_lock:
                    self._mac_cache[mac] = (definition.ip, definition.hostname, subnet_id,)
                    self._subnet_cache[subnet_id] = (
                     definition.gateway, definition.subnet_mask, definition.broadcast_address,
                     definition.domain_name, definition.domain_name_servers, definition.ntp_servers,
                     definition.lease_time
                    )
            return definition
            
class Null(Database):
    """
    A database that never serves anything, useful in case other modules provide
    definitions.
    """
    def lookupMAC(self, mac):
        """
        Queries the database for the given MAC address and returns the IP and
        associated details if the MAC is known.
        
        @type mac: basestring
        @param mac: The MAC address to lookup.
        
        @rtype: None
        @return: Nothing, because no data is managed.
        """
        return None
        
    def reinitialise(self):
        """
        Though subclass-dependent, this will generally result in some guarantee
        that the database will provide fresh data, whether that means flushing
        a cache or reconnecting to the source.
        """
        