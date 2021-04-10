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

(C) Neil Tallim, 2021 <flan@uguu.ca>
"""
import json
import logging
import threading

from .generic import (Database, Definition)

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
        _logger.debug("Initialising database-cache '{}'...".format(self))
        self._cache_lock = threading.Lock()
        if chained_cache:
            self._chained_cache = chained_cache
            _logger.debug("Chained database-cache: {}".format(chained_cache))

    def __str__(self):
        return "{} <{} : 0x{:x}>".format(
            self._name,
            self.__class__.__name__,
            id(self),
        )

    def reinitialise(self):
        _logger.debug("Reinitialising database-cache '{}'...".format(self))
        with self._cache_lock:
            self._reinitialise()
            if self._chained_cache:
                self._chained_cache.reinitialise()
        _logger.debug("Reinitialised database-cache '{}'".format(self))
    def _reinitialise(self): pass

    def lookupMAC(self, mac):
        _mac = str(mac)
        _logger.debug("Searching for '{}' in database-cache '{}'...".format(_mac, self))
        with self._cache_lock:
            definition = self._lookupMAC(mac)

        if not definition:
            _logger.debug("No match for '{}' in database-cache '{}'".format(_mac, self))
            if self._chained_cache:
                definition = self._chained_cache.lookupMAC(mac)
                if definition:
                    self.cacheMAC(mac, definition, chained=True)
        else:
            _logger.debug("Found a match for '{}' in database-cache '{}'".format(_mac, self))

        return definition
    def _lookupMAC(self, mac): return None

    def cacheMAC(self, mac, definition, chained=False):
        _logger.debug("Setting definition for '{}' in database-cache '{}'...".format(mac, self))
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
        cache = self._mac_cache.get(int(mac))
        if cache:
            definitions = []
            for data in cache:
                (ip, hostname, extra, subnet_id) = data
                details = self._subnet_cache[subnet_id]
                definitions.append(Definition(
                    ip=ip, lease_time=details[6], subnet=subnet_id[0], serial=subnet_id[1],
                    hostname=hostname,
                    gateways=details[0], subnet_mask=details[1], broadcast_address=details[2],
                    domain_name=details[3], domain_name_servers=details[4], ntp_servers=details[5],
                    extra=extra,
                ))
            if definitions:
                if len(definitions) == 1:
                    return definitions[0]
                return definitions
        return None

    def _cacheMAC(self, mac, definition, chained):
        if isinstance(definition, Definition):
            definitions = (definition,)
        else:
            definitions = definition
            
        mac_cache = []
        for definition in definitions:
            subnet_id = (definition.subnet, definition.serial)
            mac_cache.append((definition.ip, definition.hostname, definition.extra, subnet_id))
            self._subnet_cache[subnet_id] = (
                definition.gateways, definition.subnet_mask, definition.broadcast_address,
                definition.domain_name, definition.domain_name_servers, definition.ntp_servers,
                definition.lease_time,
            )
        self._mac_cache[int(mac)] = mac_cache


class MemcachedCache(_DatabaseCache):
    """
    A memory database cache using memcache.
    """
    _mac_cache = None #: A dictionary of cached MACs
    _subnet_cache = None #: A dictionary of cached subnet/serial data

    def __init__(self, name, memcached_server_data, memcached_age_time, chained_cache=None):
        """
        Initialises the cache.

        :param basestring name: The name of the cache.
        :param tuple memcached_server_data: Address and port to connect to the memcached server.
        :param basestring memcached_age_time: number of seconds to store items in memcache.
        :param :class:`_DatabaseCache <_DatabaseCache>` chained_cache: The next
            node in the chain; None if this is the end.
        """
        _DatabaseCache.__init__(self, name, chained_cache=chained_cache)
        import pymemcache.client.base
        self.mc_client = pymemcache.client.base.Client(
            (memcached_server_data[0], memcached_server_data[1]),
            connect_timeout=1.0, timeout=1.0,
        )
        self.memcached_age_time = memcached_age_time
        _logger.debug("Memcached database-cache initialised")

    def _lookupMAC(self, mac):
        data = self.mc_client.get(str(mac))
        if data:
            pending = {}
            for datum in json.loads(data):
                (_, _, _, subnet_id) = datum
                pending[self._create_subnet_key(subnet_id)] = datum
                
            results = []
            for (key, details) in self.mc_client.get_many(list(pending)).items():
                if details:
                    details = json.loads(details)
                    (ip, hostname, extra, subnet_id) = pending[key]
                    results.append(Definition(
                        ip=ip, lease_time=details[6], subnet=subnet_id[0], serial=subnet_id[1],
                        hostname=hostname,
                        gateways=details[0], subnet_mask=details[1], broadcast_address=details[2],
                        domain_name=details[3], domain_name_servers=details[4], ntp_servers=details[5],
                        extra=extra,
                    ))
            if results:
                if len(results) == 1:
                    return results[0]
                return results
        return None

    def _cacheMAC(self, mac, definition, chained):
        if isinstance(definition, Definition):
            definitions = (definition,)
        else:
            definitions = definition

        cache_records = {}
        mac_list = []
        for definition in definitions:
            subnet_id = (definition.subnet, definition.serial)
            mac_list.append((definition.ip and str(definition.ip), definition.hostname, definition.extra, subnet_id))
            cache_records[self._create_subnet_key(subnet_id)] = json.dumps((
                definition.gateways, definition.subnet_mask, definition.broadcast_address,
                definition.domain_name, definition.domain_name_servers, definition.ntp_servers,
                definition.lease_time,
            ))
        cache_records[str(mac)] = json.dumps(mac_list)
        self.mc_client.set_many(cache_records, expire=self.memcached_age_time)
        
    def _create_subnet_key(self, subnet_id):
        return "{}-{}".format(subnet_id[0].replace(" ", "_"), subnet_id[1])


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
        _logger.debug("On-disk database-cache initialised at {}".format(self._filepath))

    def _connect(self):
        database = self._sqlite3.connect(self._filepath)
        return (database, database.cursor())

    def _disconnect(self, database, cursor):
        try:
            cursor.close()
        except Exception as e:
            _logger.warning("Unable to close cache cursor: {}".format(e))
        try:
            database.close()
        except Exception as e:
            _logger.warning("Unable to close cache database: {}".format(e))

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
            details TEXT
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
        definitions = []
        
        (database, cursor) = self._connect()
        cursor.execute("""SELECT
            details
        FROM maps
        WHERE
            mac = ?
        LIMIT 1""", (int(mac),))
        result = cursor.fetchone()
        if result:
            for (ip, hostname, extra, subnet, serial) in json.loads(result):
                cursor.execute("""SELECT
                    gateway, subnet_mask, broadcast_address, domain_name, domain_name_servers,
                    ntp_servers, lease_time
                FROM subnets
                WHERE
                    subnet = ? AND
                    serial = ?
                LIMIT 1""", (subnet, serial,))
                result = cursor.fetchone()
                if result:
                    definitions.append(Definition(
                        ip=ip, hostname=hostname,
                        gateways=result[0], subnet_mask=result[1], broadcast_address=result[2],
                        domain_name=result[3], domain_name_servers=result[4], ntp_servers=result[5],
                        lease_time=result[6], subnet=subnet, serial=serial,
                        extra=extra,
                    ))
        self._disconnect(database, cursor)
        
        if definitions:
            if len(definitions) == 1:
                return definitions[0]
            return definitions
        return None

    def _cacheMAC(self, mac, definition, chained):
        if isinstance(definition, Definition):
            definitions = (definition,)
        else:
            definitions = definition
            
        mac_list = []
        for definition in definitions:
            mac_list.append((definition.ip and str(definition.ip), definition.hostname, definition.extra, definition.subnet, definition.serial))
            
        (database, cursor) = self._connect()
        cursor.execute("""INSERT OR IGNORE INTO subnets (
            subnet, serial,
            lease_time,
            gateway,
            subnet_mask,
            broadcast_address,
            ntp_servers,
            domain_name_servers,
            domain_name
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", (
            definition.subnet, definition.serial,
            definition.lease_time,
            definition.gateways and ','.join(str(i) for i in definition.gateways),
            definition.subnet_mask and str(definition.subnet_mask),
            definition.broadcast_address and str(definition.broadcast_address),
            definition.ntp_servers and ','.join(str(i) for i in definition.ntp_servers),
            definition.domain_name_servers and ','.join(str(i) for i in definition.domain_name_servers),
            definition.domain_name,
        ))
        cursor.execute("""INSERT OR REPLACE INTO maps (
            mac, details
        ) VALUES (?, ?)""", (
            int(mac), json.dumps(mac_list),
        ))
        database.commit()
        self._disconnect(database, cursor)
