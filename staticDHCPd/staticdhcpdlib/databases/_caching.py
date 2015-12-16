# -*- encoding: utf-8 -*-
"""
staticdhcpdlib.databases._caching
=================================
Defines caching structures for databases.

Legal
-----
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

(C) Neil Tallim, 2014 <flan@uguu.ca>
"""
import json
import logging
import threading

from generic import (Database, Definition)

_logger = logging.getLogger('databases._caching')

class _DatabaseCache(Database):
    """
    A node in a caching chain.
    """
    _cache_lock = None #: A lock to prevent race conditions
    _chained_cache = None #: The next node in the caching chain
    _name = None #: The name of this node

    def __init__(self, name, chained_cache=None):
        """
        Initialises a node in a caching chain.

        :param basestring name: The name of the cache.
        :param :class:`_DatabaseCache <_DatabaseCache>` chained_cache: The next
            node in the chain; None if this is the end.
        """
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
    """
    An optimised in-memory database cache.
    """
    _mac_cache = None #: A dictionary of cached MACs
    _subnet_cache = None #: A dictionary of cached subnet/serial data

    def __init__(self, name, chained_cache=None):
        """
        Initialises the cache.

        :param basestring name: The name of the cache.
        :param :class:`_DatabaseCache <_DatabaseCache>` chained_cache: The next
            node in the chain; None if this is the end.
        """
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
            (ip, hostname, extra, subnet_id) = data
            details = self._subnet_cache[subnet_id]
            return Definition(
             ip=ip, lease_time=details[6], subnet=subnet_id[0], serial=subnet_id[1],
             hostname=hostname,
             gateways=details[0], subnet_mask=details[1], broadcast_address=details[2],
             domain_name=details[3], domain_name_servers=details[4], ntp_servers=details[5],
             extra=extra
            )
        return None

    def _cacheMAC(self, mac, definition, chained):
        subnet_id = (definition.subnet, definition.serial)
        self._mac_cache[int(mac)] = (definition.ip, definition.hostname, definition.extra, subnet_id)
        self._subnet_cache[subnet_id] = (
         definition.gateways, definition.subnet_mask, definition.broadcast_address,
         definition.domain_name, definition.domain_name_servers, definition.ntp_servers,
         definition.lease_time
        )

class MemcachedCache(_DatabaseCache):
    """
    A memory database cache using memcache.
    """
    _mac_cache = None #: A dictionary of cached MACs
    _subnet_cache = None #: A dictionary of cached subnet/serial data

    def __init__(self, name, memcached_server, memcached_age_time, chained_cache=None):
        """
        Initialises the cache.

        :param basestring name: The name of the cache.
        :param basestring memcached_server: Address and port to connect to the memcached server.
        :param basestring memcached_age_time: number of seconds to store items in memcache.
        :param :class:`_DatabaseCache <_DatabaseCache>` chained_cache: The next
            node in the chain; None if this is the end.
        """
        _DatabaseCache.__init__(self, name, chained_cache=chained_cache)
        import memcache

        self.mc_client = memcache.Client([memcached_server])
        self.memcached_age_time = memcached_age_time
        _logger.debug("Memcached database-cache initialised")

    def _reinitialise(self):
        self.mc_client.flush_all()

    def _lookupMAC(self, mac):
        data = self.mc_client.get(str(mac))
        if data:
            (ip, hostname, extra, subnet_id) = data
            subnet_str = "%s-%s" % subnet_id
            details = self.mc_client.get(subnet_str)
            return Definition(
             ip=ip, lease_time=details[6], subnet=subnet_id[0], serial=subnet_id[1],
             hostname=hostname,
             gateways=details[0], subnet_mask=details[1], broadcast_address=details[2],
             domain_name=details[3], domain_name_servers=details[4], ntp_servers=details[5],
             extra=extra
            )
        return None

    def _cacheMAC(self, mac, definition, chained):
        subnet_id = (definition.subnet, definition.serial)
        subnet_str = "%s-%s" % subnet_id
        self.mc_client.set(str(mac), (definition.ip, definition.hostname, definition.extra, subnet_id), self.memcached_age_time)
        self.mc_client.set(subnet_str, (
         definition.gateways, definition.subnet_mask, definition.broadcast_address,
         definition.domain_name, definition.domain_name_servers, definition.ntp_servers,
         definition.lease_time
         ), self.memcached_age_time)

class DiskCache(_DatabaseCache):
    _filepath = None #: The path to which the persistent file will be written
    _sqlite3 = None #: A reference to the sqlite3 module

    def __init__(self, name, filepath, chained_cache=None):
        """
        Initialises the cache.

        :param basestring name: The name of the cache.
        :param basestring filepath: The path to which a persistent on-disk
                                    cache is written; if None, a tempfile is
                                    used.
        :param :class:`_DatabaseCache <_DatabaseCache>` chained_cache: The next
            node in the chain; None if this is the end.
        """
        _DatabaseCache.__init__(self, name, chained_cache=chained_cache)

        import sqlite3
        self._sqlite3 = sqlite3

        if filepath:
            self._filepath = filepath
        else:
            import tempfile
            #Assigned to self so that the file stays open
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
    serial INTEGER,
    extra TEXT
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
 s.ntp_servers, s.lease_time, s.subnet, s.serial,
 m.extra
FROM maps m, subnets s
WHERE
 m.mac = ? AND m.subnet = s.subnet AND m.serial = s.serial
LIMIT 1""", (int(mac),))
        result = cursor.fetchone()
        self._disconnect(database, cursor)
        if result:
            return Definition(
             ip=result[0], hostname=result[1],
             gateways=result[2], subnet_mask=result[3], broadcast_address=result[4],
             domain_name=result[5], domain_name_servers=result[6], ntp_servers=result[7],
             lease_time=result[8], subnet=result[9], serial=result[10],
             extra=json.loads(result[11])
            )
        return None

    def _cacheMAC(self, mac, definition, chained):
        (database, cursor) = self._connect()
        cursor.execute("INSERT OR IGNORE INTO subnets (subnet, serial, lease_time, gateway, subnet_mask, broadcast_address, ntp_servers, domain_name_servers, domain_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
         (
          definition.subnet, definition.serial,
          definition.lease_time,
          definition.gateways and ','.join(str(i) for i in definition.gateways),
          definition.subnet_mask and str(definition.subnet_mask),
          definition.broadcast_address and str(definition.broadcast_address),
          definition.ntp_servers and ','.join(str(i) for i in definition.ntp_servers),
          definition.domain_name_servers and ','.join(str(i) for i in definition.domain_name_servers),
          definition.domain_name
         )
        )
        cursor.execute("INSERT INTO maps (mac, ip, hostname, subnet, serial, extra) VALUES (?, ?, ?, ?, ?, ?)",
         (
          int(mac),
          definition.ip and str(definition.ip), definition.hostname,
          definition.subnet, definition.serial,
          json.dumps(definition.extra)
         )
        )
        database.commit()
        self._disconnect(database, cursor)
