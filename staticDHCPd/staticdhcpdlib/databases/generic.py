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
 (C) Anthony Woods, 2013 <awoods@internap.com>
"""
try:
    from types import StringTypes
except ImportError: #py3k
    StringTypes = (str,)

import collections
import logging
import threading
import traceback
from libpydhcpserver.dhcp_types.ipv4 import IPv4

_logger = logging.getLogger('databases.generic')

class Definition(object):
    ip = None
    hostname = None
    gateway = None
    subnet_mask = None
    broadcast_address = None
    domain_name = None
    domain_name_servers = None
    ntp_servers = None
    lease_time = None
    subnet = None
    serial = None
    extra = None

    def __init__(self, ip, lease_time, subnet, serial,
        hostname=None,
        gateway=None, subnet_mask=None, broadcast_address=None,
        domain_name=None, domain_name_servers=None, ntp_servers=None,
        extra=None):
        
        #Required values
        self.ip = IPv4(ip)
        self.lease_time = lease_time
        self.subnet = subnet
        self.serial = serial
        
        #Optional vlaues
        self.hostname = hostname
        self.gateway = gateway and IPv4(gateway)
        self.subnet_mask = subnet_mask and IPv4(subnet_mask)
        self.broadcast_address = broadcast_address and IPv4(broadcast_address)
        self.domain_name = domain_name
        if domain_name_servers:
            if isinstance(domain_name_servers, StringTypes):
                domain_name_servers = domain_name_servers.split(',')
            self.domain_name_servers = [IPv4(i) for i in domain_name_servers[:3]]
        if ntp_servers:
            if isinstance(ntp_servers, StringTypes):
                ntp_servers = ntp_servers.split(',')
            self.ntp_servers = [IPv4(i) for i in ntp_servers[:3]]
        self.extra = extra or None
        
        
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
        
class CachingDatabase(Database):
    """
    A partial implementation of the Database engine, adding generic caching
    logic and concurrency-throttling.
    """
    _resource_lock = None #: A lock used to prevent the database from being overwhelmed.
    _cache = None #: The caching structure to use, if caching is desired.
    
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
        try:
            self._setupCache()
        except Exception, e:
            _logger.error("Cache initialisation failed:\n" + traceback.format_exc())
            
    def _setupCache(self):
        """
        Sets up the database caching environment.
        """
        from .. import config
        if config.USE_CACHE:
            import _caching
            if config.PERSISTENT_CACHE or config.CACHE_ON_DISK:
                try:
                    disk_cache = _caching.DiskCache(config.PERSISTENT_CACHE and 'persistent' or 'disk', config.PERSISTENT_CACHE)
                    if config.CACHE_ON_DISK:
                        _logger.debug("Combining local caching database and persistent caching database")
                        self._cache = disk_cache
                    else:
                        _logger.debug("Setting up memory-cache on top of persistent caching database")
                        self._cache = _caching.MemoryCache('memory', chained_cache=disk_cache)
                except Exception, e:
                    _logger.error("Unable to initialise disk-based caching:\n" + traceback.format_exc())
                    if config.PERSISTENT_CACHE and not config.CACHE_ON_DISK:
                        _logger.warn("Persistent caching is not available")
                        self._cache = _caching.MemoryCache('memory-nonpersist')
                    elif config.CACHE_ON_DISK:
                        _logger.warn("Caching is disabled: memory-caching was not requested, so no fallback exists")
            else:
                _logger.debug("Setting up memory-cache")
                self._cache = _caching.MemoryCache('memory')
                
            if self._cache:
                _logger.info("Database caching enabled; top-level cache: " + str(self._cache))
            else:
                _logger.warn("Database caching could not be enabled")
        else:
            if config.PERSISTENT_CACHE:
                _logger.warn("PERSISTENT_CACHE was set, but USE_CACHE was not")
            if config.CACHE_ON_DISK:
                _logger.warn("CACHE_ON_DISK was set, but USE_CACHE was not")
                
    def reinitialise(self):
        if self._cache:
            try:
                self._cache.reinitialise()
            except Exception, e:
                _logger.error("Cache reinitialisation failed:\n" + traceback.format_exc())
                
    def lookupMAC(self, mac):
        if self._cache:
            try:
                definition = self._cache.lookupMAC(mac)
            except Exception, e:
                _logger.error("Cache lookup failed:\n" + traceback.format_exc())
            else:
                if definition:
                    return definition
                    
        with self._resource_lock:
            definition = self._lookupMAC(mac)
        if definition and self._cache:
            try:
                self._cache.cacheMAC(mac, definition)
            except Exception, e:
                _logger.error("Cache update failed:\n" + traceback.format_exc())
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
        
