# -*- encoding: utf-8 -*-
"""
staticDHCPd module: src.sql

Purpose
=======
 Provides a uniform datasource API, selecting from multiple backends,
 for a staticDHCPd server.
 
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
 
 (C) Neil Tallim, 2009 <red.hamsterx@gmail.com>
"""
################################################################################
#   The decision of which engine to use occurs at the bottom of this module    #
# The chosen class is made accessible via the module-level SQL_BROKER variable #
################################################################################
import threading

import conf

import src.logging

class _SQLBroker(object):
    """
    A stub documenting the features an _SQLBroker object must provide.
    """
    _resource_lock = None #: A lock used to prevent the database from being overwhelmed.
    _cache_lock = None #: A lock used to prevent multiple simultaneous cache updates.
    _mac_cache = None #: A cache used to prevent unnecessary database hits.
    _subnet_cache = None #: A cache used to prevent unnecessary database hits.
    
    def __init__(self):
        """
        Sets up the SQL broker cache.
        """
        self._cache_lock = threading.Lock()
        self._mac_cache = {}
        self._subnet_cache = {}

    def _closeConnection(self, connection):
        """
        Disposes of a connection.

        @param connection: The connection object to be disposed of.
        """
        raise NotImplementedError("_closeConnection must be overridden")
        
    def _getConnection(self):
        """
        Provides a connection to the database.

        @return: The connection object to be used.

        @raise Exception: If a problem occurs while accessing the database.
        """
        raise NotImplementedError("_getConnection must be overridden")
        
    def flushCache(self):
        """
        Resets the cache to an empty state, forcing all lookups to pull fresh
        data.
        """
        if conf.USE_CACHE:
            self._cache_lock.acquire()
            try:
                self._mac_cache = {}
                self._subnet_cache = {}
                src.logging.writeLog("Flushed DHCP cache")
            finally:
                self._cache_lock.release()
                
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
        if conf.USE_CACHE:
            self._cache_lock.acquire()
            try:
                data = self._mac_cache.get(mac)
                if data:
                    (ip, hostname, subnet_id) = data
                    return (ip, hostname,) + self._subnet_cache[subnet_id] + subnet_id
            finally:
                self._cache_lock.release()
                
        self._resource_lock.acquire()
        try:
            data = self._lookupMAC(mac)
            if conf.USE_CACHE:
                if data:
                    (ip, hostname,
                     gateway, subnet_mask, broadcast_address,
                     domain_name, domain_name_servers, ntp_servers,
                     lease_time, subnet, serial) = data
                    subnet_id = (subnet, serial)
                    self._cache_lock.acquire()
                    try:
                        self._mac_cache[mac] = (ip, hostname, subnet_id,)
                        self._subnet_cache[subnet_id] = (
                         gateway, subnet_mask, broadcast_address,
                         domain_name, domain_name_servers, ntp_servers,
                         lease_time,
                        )
                    finally:
                        self._cache_lock.release()
            return data
        finally:
            self._resource_lock.release()
            
class _MySQL(_SQLBroker):
    """
    Implements a MySQL broker.
    """
    _host = None #: The address of the database's host.
    _port = None #: The port on which the database process is listening.
    _username = None #: The username with which to authenticate.
    _password = None #: The password with which to authenticate.
    _database = None #: The name of the database to be consulted.
    
    def __init__(self):
        """
        Constructs the broker.
        """
        _SQLBroker.__init__(self)
        self._resource_lock = threading.BoundedSemaphore(conf.MYSQL_MAXIMUM_CONNECTIONS)
        
        if conf.MYSQL_HOST is None:
            self._host = 'localhost'
        else:
            self._host = conf.MYSQL_HOST
            self._port = cont.MYSQL_PORT
        self._username = conf.MYSQL_USERNAME
        self._password = conf.MYSQL_PASSWORD
        self._database = conf.MYSQL_DATABASE

    def _closeConnection(self, connection):
        """
        Disposes of a connection.

        @param connection: The connection object to be disposed of.
        """
        try:
            connection.close()
        except Exception:
            pass
            
    def _getConnection(self):
        """
        Provides a connection to the database.

        @return: The connection object to be used.

        @raise Exception: If a problem occurs while accessing the database.
        """
        if not self._port is None:
            return MySQLdb.connect(
             host=self._host, port=self._port, db=self._database,
             user=self._username, passwd=self._password,
            )
        else:
            return MySQLdb.connect(
             host=self._host, db=self._database,
             user=self._username, passwd=self._password
            )

    def _lookupMAC(self, mac):
        """
        Queries the database for the given MAC address and returns the IP and
        associated details if the MAC is known.
        
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
        try:
            mysql_db = self._getConnection()
            mysql_cur = mysql_db.cursor()
            
            mysql_cur.execute("""
             SELECT
              m.ip, m.hostname,
              s.gateway, s.subnet_mask, s.broadcast_address, s.domain_name, s.domain_name_servers,
              s.ntp_servers, s.lease_time, s.subnet, s.serial
             FROM maps m, subnets s
             WHERE
              m.mac = %s AND m.subnet = s.subnet AND m.serial = s.serial
             LIMIT 1
            """)), (mac,))
            result = mysql_cur.fetchone()
            if result:
                return result
            return None
        finally:
            try:
                mysql_cur.close()
            except Exception:
                pass
            self._closeConnection(mysql_db)

class _DB20Broker(_SQLBroker):
    """
    Defines bevahiour for a DB API 2.0-compatible broker.
    """
    _query_mac = None #: The string used to look up a MAC's binding.
    
    def _closeConnection(self, connection):
        """
        Disposes of a connection.

        @param connection: The connection object to be disposed of.
        """
        try:
            connection.close()
        except Exception:
            pass
            
    def _lookupMAC(self, mac):
        """
        Queries the database for the given MAC address and returns the IP and
        associated details if the MAC is known.
        
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
        try:
            db = self._getConnection()
            cur = db.cursor()
            
            cur.execute(self._query_mac), (mac,))
            result = cur.fetchone()
            if result:
                return result
            return None
        finally:
            try:
                cur.close()
            except Exception:
                pass
            self._closeConnection(db)
            
class _PostgreSQL(_DB20Broker):
    """
    Implements a PostgreSQL broker.
    """
    _host = None #: The address of the database's host.
    _port = None #: The port on which the database process is listening.
    _username = None #: The username with which to authenticate.
    _password = None #: The password with which to authenticate.
    _database = None #: The name of the database to be consulted.
    _sslmode = None #: The SSL negotiation mode.

    _query_mac = """
     SELECT
      m.ip, m.hostname,
      s.gateway, s.subnet_mask, s.broadcast_address, s.domain_name, s.domain_name_servers,
      s.ntp_servers, s.lease_time, s.subnet, s.serial
     FROM maps m, subnets s
     WHERE
      m.mac = %s AND m.subnet = s.subnet AND m.serial = s.serial
     LIMIT 1
    """
    
    def __init__(self):
        """
        Constructs the broker.
        """
        _SQLBroker.__init__(self)
        self._resource_lock = threading.BoundedSemaphore(conf.POSTGRESQL_MAXIMUM_CONNECTIONS)
        
        if conf.POSTGRESQL_HOST is None:
            self._host = 'localhost'
        else:
            self._host = conf.POSTGRESQL_HOST
            self._port = cont.POSTGRESQL_PORT
        self._username = conf.POSTGRESQL_USERNAME
        self._password = conf.POSTGRESQL_PASSWORD
        self._database = conf.POSTGRESQL_DATABASE
        self._sslmode = conf.POSTGRESQL_SSLMODE

    def _getConnection(self):
        """
        Provides a connection to the database.

        @return: The connection object to be used.
        
        @raise Exception: If a problem occurs while accessing the database.
        """
        if not self._port is None:
            return psycopg2.connect(
             host=self._host, port=self._port, database=self._database, sslmode=self._sslmode,
             user=self._username, password=self._password,
            )
        else:
            return psycopg2.connect(
             database=self._database,
             user=self._username, password=self._password,
            )

class _SQLite(_DB20Broker):
    """
    Implements a SQLite broker.
    """
    _file = None #: The path to the file containing the SQLite3 database to be used.

    _query_mac = """
     SELECT
      m.ip, m.hostname,
      s.gateway, s.subnet_mask, s.broadcast_address, s.domain_name, s.domain_name_servers,
      s.ntp_servers, s.lease_time, s.subnet, s.serial
     FROM maps m, subnets s
     WHERE
      m.mac = ? AND m.subnet = s.subnet AND m.serial = s.serial
     LIMIT 1
    """
    
    def __init__(self):
        """
        Constructs the broker.
        """
        _SQLBroker.__init__(self)
        self._resource_lock = threading.BoundedSemaphore(conf.SQLITE_MAXIMUM_CONNECTIONS)
        
        self._file = conf.SQLITE_FILE

    def _getConnection(self):
        """
        Provides a connection to the database.

        @return: The connection object to be used.
        
        @raise Exception: If a problem occurs while accessing the database.
        """
        return sqlite3.connect(self._file)
        
#Decide which SQL engine to use and store the class in SQL_BROKER.
SQL_BROKER = None #: The class of the SQL engine to use for looking up MACs.
if conf.DATABASE_ENGINE == 'MySQL':
    import MySQLdb
    SQL_BROKER = _MySQL
elif conf.DATABASE_ENGINE == 'PostgreSQL':
    import psycopg2
    SQL_BROKER = _PostgreSQL
elif conf.DATABASE_ENGINE == 'SQLite':
    import sqlite3
    SQL_BROKER = _SQLite
else:
    raise ValueError("Unknown database engine: %(engine)s" % {
     'engine': conf.DATABASE_ENGINE
    })
    
