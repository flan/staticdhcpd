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
import threading
import traceback

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
        
class _DatabaseCache(object):
    _cache_lock = None
    _chained_cache = None
    _name = None
    
    def __init__(self, name, chained_cache=None):
        self._name = name
        _logger.debug("Initialising database-cache '%(id)s'..." % {
         'id': self,
        })
        self._cache_lock = threading.Lock()
        if chained_cache:
            self._chained_cache = chained_cache
            _logger.debug("Chained database-cache: %(chained)s" % {
             'chained': chained_cache,
            })
            
    def __str__(self):
        return "%(name)s <%(type)s : 0x%(id)x>" % {
         'name': self._name,
         'type': self.__class__.__name__,
         'id': id(self),
        }
        
    def reinitialise(self):
        _logger.debug("Reinitialising database-cache '%(id)s'..." % {
         'id': self,
        })
        with self._cache_lock:
            self._reinitialise()
            if self._chained_cache:
                self._chained_cache.reinitialise()
        _logger.debug("Reinitialised database-cache '%(id)s'" % {
         'id': self,
        })
    def _reinitialise(self): pass
        
    def lookupMAC(self, mac):
        _mac = str(mac)
        _logger.debug("Searching for '%(mac)s' in database-cache '%(id)s'..." % {
         'mac': _mac,
         'id': self,
        })
        with self._cache_lock:
            definition = self._lookupMAC(mac)
            
        if not definition:
            _logger.debug("No match for '%(mac)s' in database-cache '%(id)s'" % {
             'mac': _mac,
             'id': self,
            })
            if self._chained_cache:
                definition = self._chained_cache.lookupMAC(mac)
                if definition:
                    self.cacheMAC(mac, definition, chained=True)
        else:
            _logger.debug("Found a match for '%(mac)s' in database-cache '%(id)s'" % {
             'mac': _mac,
             'id': self,
            })
            
        return definition
    def _lookupMAC(self, mac): return None
    
    def cacheMAC(self, mac, definition, chained=False):
        _logger.debug("Setting definition for '%(mac)s' in database-cache '%(id)s'..." % {
         'mac': mac,
         'id': self,
        })
        with self._cache_lock:
            self._cacheMAC(mac, definition, chained=chained)
            
        if self._chained_cache and not chained:
            self._chained_cache.cacheMAC(mac, definition, chained=False)
    def _cacheMAC(self, mac, definition, chained): pass
    
class _MemoryCache(_DatabaseCache):
    _persistent_cache = None
    
    def __init__(self, name, chained_cache=None):
        _DatabaseCache.__init__(self, name, chained_cache=chained_cache)
        
        self._mac_cache = {}
        self._subnet_cache = {}
        _logger.debug("In-memory database-cache initialised")
        
    def _reinitialise(self):
        self._mac_cache.clear()
        self._subnet_cache.clear()
        
    def _lookupMAC(self, mac):
        data = self._mac_cache.get(int(mac))
        if data:
            (ip, hostname, subnet_id) = data
            return Definition(*((ip, hostname,) + self._subnet_cache[subnet_id] + subnet_id))
        return None
        
    def _cacheMAC(self, mac, definition, chained):
        subnet_id = (definition.subnet, definition.serial)
        self._mac_cache[int(mac)] = (definition.ip, definition.hostname, subnet_id)
        self._subnet_cache[subnet_id] = (
         definition.gateway, definition.subnet_mask, definition.broadcast_address,
         definition.domain_name, definition.domain_name_servers, definition.ntp_servers,
         definition.lease_time
        )
        
class _DiskCache(_DatabaseCache):
    _filepath = None
    
    def __init__(self, name, filepath, chained_cache=None):
        _DatabaseCache.__init__(self, name, chained_cache=chained_cache)
        
        if filepath:
            self._filepath = filepath
        else:
            import tempfile
            self.__tempfile = tempfile.NamedTemporaryFile()
            self._filepath = self.__tempfile.name
            
        self._setupDatabase()
        _logger.debug("On-disk database-cache initialised at " + self._filepath)
        
    def _connect(self):
        import sqlite3
        database = sqlite3.connect(self._filepath)
        return (database, database.cursor())
        
    def _disconnect(self, database, cursor):
        try:
            cursor.close()
        except Exception, e:
            _logger.warn("Unable to close cache cursor: " + str(e))
        try:
            database.close()
        except Exception, e:
            _logger.warn("Unable to close cache database: " + str(e))
            
    def _setupDatabase(self):
        (database, cursor) = self._connect()
        
        #These definitions omit a lot of integrity logic, since the underlying database is to enforce that
        cursor.execute("""CREATE TABLE IF NOT EXISTS subnets (
    subnet TEXT,
    serial INTEGER,
    lease_time INTEGER,
    gateway TEXT,
    subnet_mask TEXT,
    broadcast_address TEXT,
    ntp_servers TEXT,
    domain_name_servers TEXT,
    domain_name TEXT,
    PRIMARY KEY(subnet, serial)
)""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS maps (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    hostname TEXT,
    subnet TEXT,
    serial INTEGER
)""")
        database.commit()
        self._disconnect(database, cursor)
        
    def _reinitialise(self):
        (database, cursor) = self._connect()
        cursor.execute("DELETE FROM maps")
        cursor.execute("DELETE FROM subnets")
        database.commit()
        self._disconnect(database, cursor)
        
    def _lookupMAC(self, mac):
        (database, cursor) = self._connect()
        cursor.execute("""SELECT
 m.ip, m.hostname,
 s.gateway, s.subnet_mask, s.broadcast_address, s.domain_name, s.domain_name_servers,
 s.ntp_servers, s.lease_time, s.subnet, s.serial
FROM maps m, subnets s
WHERE
 m.mac = ? AND m.subnet = s.subnet AND m.serial = s.serial
LIMIT 1""", (str(mac),))
        result = cursor.fetchone()
        self._disconnect(database, cursor)
        if result:
            return Definition(*result)
        return None
        
    def _cacheMAC(self, mac, definition, chained):
        (database, cursor) = self._connect()
        cursor.execute("INSERT INTO OR IGNORE subnets (subnet, serial, lease_time, gateway, subnet_mask, broadcast_address, ntp_servers, domain_name_servers, domain_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
         (
          definition.subnet, definition.serial,
          definition.lease_time,
          definition.gateway, definition.subnet_mask, definition.broadcast_address,
          definition.ntp_servers, definition.domain_name_servers, definition.domain_name
         )
        )
        cursor.execute("INSERT INTO maps (mac, ip, hostname, subnet, serial) VALUES (?, ?, ?, ?, ?)",
         (
          str(mac),
          definition.ip, definition.hostname,
          definition.subnet, definition.serial
         )
        )
        database.commit()
        self._disconnect(database, cursor)
        
        
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
            if config.PERSISTENT_CACHE or config.CACHE_ON_DISK:
                try:
                    disk_cache = _DiskCache(config.PERSISTENT_CACHE and 'persistent' or 'disk', config.PERSISTENT_CACHE)
                    if config.CACHE_ON_DISK:
                        _logger.debug("Combining local caching database and persistent caching database")
                        self._cache = disk_cache
                    else:
                        _logger.debug("Setting up memory-cache on top of persistent caching database")
                        self._cache = _MemoryCache('memory', chained_cache=disk_cache)
                except Exception, e:
                    _logger.error("Unable to initialise disk-based caching:\n" + traceback.format_exc())
                    if config.PERSISTENT_CACHE and not config.CACHE_ON_DISK:
                        _logger.warn("Persistent caching is not available")
                        self._cache = _MemoryCache('memory-nonpersist')
                    elif config.CACHE_ON_DISK:
                        _logger.warn("Caching is disabled: memory-caching was not requested, so no fallback exists")
            else:
                _logger.debug("Setting up memory-cache")
                self._cache = _MemoryCache('memory')
                
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
        
