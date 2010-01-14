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
 
 (C) Neil Tallim, 2009
"""
###############################################################################
#   The decision of which engine to use occurs at the bottom of this module   #
# The chosen class is made accessible via the module-level SQL_BROKER variable#
###############################################################################
import threading

import conf

class _SQLBroker(object):
	"""
	A stub documenting the features an _SQLBroker object must provide.
	"""
	_resource_lock = None #: A lock used to prevent the database from being overwhelmed.
	
	def lookupMAC(self, mac):
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
		self._resource_lock.acquire()
		try:
			return self._lookupMAC(mac)
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
		self._resource_lock = threading.BoundedSemaphore(conf.MYSQL_MAXIMUM_CONNECTIONS)
		
		if conf.MYSQL_HOST is None:
			self._host = 'localhost'
		else:
			self._host = conf.MYSQL_HOST
			self._port = cont.MYSQL_PORT
		self._username = conf.MYSQL_USERNAME
		self._password = conf.MYSQL_PASSWORD
		self._database = conf.MYSQL_DATABASE
		
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
			mysql_db = None
			if not self._port is None:
				mysql_db = MySQLdb.connect(
				 host=self._host, port=self._port, db=self._database,
				 user=self._username, passwd=self._password,
				)
			else:
				mysql_db = MySQLdb.connect(
				 host=self._host, db=self._database,
				 user=self._username, passwd=self._password
				)
			mysql_cur = mysql_db.cursor()
			
			mysql_cur.execute(' '.join((
			 "SELECT m.ip, m.hostname,",
			 "s.gateway, s.subnet_mask, s.broadcast_address, s.domain_name, s.domain_name_servers,",
			 "s.ntp_servers, s.lease_time, s.subnet, s.serial FROM maps m, subnets s",
			 "WHERE m.mac = %s AND m.subnet = s.subnet AND m.serial = s.serial",
			 "LIMIT 1"
			)), (mac,))
			result = mysql_cur.fetchone()
			if result:
				return result
			return None
		finally:
			try:
				mysql_cur.close()
				mysql_db.close()
			except:
				pass
				
class _SQLite(_SQLBroker):
	"""
	Implements a SQLite broker.
	"""
	_file = None #: The path to the file containing the SQLite3 database to be used.
	
	def __init__(self):
		"""
		Constructs the broker.
		"""
		self._resource_lock = threading.BoundedSemaphore(conf.SQLITE_MAXIMUM_CONNECTIONS)
		
		self._file = conf.SQLITE_FILE
		
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
			sqlite_db = sqlite3.connect(self._file)
			sqlite_cur = sqlite_db.cursor()
			
			sqlite_cur.execute(' '.join((
			 "SELECT m.ip, m.hostname,",
			 "s.gateway, s.subnet_mask, s.broadcast_address, s.domain_name, s.domain_name_servers,",
			 "s.ntp_servers, s.lease_time, s.subnet, s.serial FROM maps m, subnets s",
			 "WHERE m.mac = ? AND m.subnet = s.subnet AND m.serial = s.serial",
			 "LIMIT 1"
			)), (mac,))
			result = sqlite_cur.fetchone()
			if result:
				return result
			return None
		finally:
			try:
				sqlite_cur.close()
				sqlite_db.close()
			except:
				pass
				
#Decide which SQL engine to use and store the class in SQL_BROKER.
SQL_BROKER = None #: The class of the SQL engine to use for looking up MACs.
if conf.DATABASE_ENGINE == 'MySQL':
	import MySQLdb
	SQL_BROKER = _MySQL
elif conf.DATABASE_ENGINE == 'SQLite':
	import sqlite3
	SQL_BROKER = _SQLite
else:
	raise ValueError("Unknown database engine: %(engine)s" % {
	 'engine': conf.DATABASE_ENGINE
	})
	