# -*- encoding: utf-8 -*-
"""
staticDHCPd module: databases._caching

Purpose
=======
 Defines caching structures for databases.
 
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

from generic import (Database, Definition)

_logger = logging.getLogger('databases._caching')

class _DatabaseCache(Database):
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
    
class MemoryCache(_DatabaseCache):
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
        
class DiskCache(_DatabaseCache):
    _filepath = None
    _sqlite3 = None
    
    def __init__(self, name, filepath, chained_cache=None):
        _DatabaseCache.__init__(self, name, chained_cache=chained_cache)
        
        import sqlite3
        self._sqlite3 = sqlite3
        
        if filepath:
            self._filepath = filepath
        else:
            import tempfile
            self.__tempfile = tempfile.NamedTemporaryFile()
            self._filepath = self.__tempfile.name
            
        self._setupDatabase()
        _logger.debug("On-disk database-cache initialised at " + self._filepath)
        
    def _connect(self):
        database = self._sqlite3.connect(self._filepath)
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
    mac INTEGER PRIMARY KEY,
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
LIMIT 1""", (int(mac),))
        result = cursor.fetchone()
        self._disconnect(database, cursor)
        if result:
            return Definition(*result)
        return None
        
    def _cacheMAC(self, mac, definition, chained):
        (database, cursor) = self._connect()
        cursor.execute("INSERT OR IGNORE INTO subnets (subnet, serial, lease_time, gateway, subnet_mask, broadcast_address, ntp_servers, domain_name_servers, domain_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
         (
          definition.subnet, definition.serial,
          definition.lease_time,
          definition.gateway, definition.subnet_mask, definition.broadcast_address,
          definition.ntp_servers, definition.domain_name_servers, definition.domain_name
         )
        )
        cursor.execute("INSERT INTO maps (mac, ip, hostname, subnet, serial) VALUES (?, ?, ?, ?, ?)",
         (
          int(mac),
          definition.ip, definition.hostname,
          definition.subnet, definition.serial
         )
        )
        database.commit()
        self._disconnect(database, cursor)
        
