# -*- encoding: utf-8 -*-
"""
staticDHCPd module: src.sql

Purpose
=======
 Provides a uniform SQL API for a staticDHCPd server.
 
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
	_resource_lock = None
	
	def lookupMAC(self, mac):
		self._resource_lock.acquire()
		try:
			return self._lookupMAC(mac)
		finally:
			self._resource_lock.release()
			
class _MySQL(_SQLBroker):
	_host = None
	_port = None
	_username = None
	_password = None
	_database = None
	
	def __init__(self):
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
		May raise exception.
		"""
		try:
			mysql_db = None
			if not self._port is None:
				mysql_db = MySQLdb.connect(
				 host=self._host, port=self._port, user=self._username, passwd=self._password, db=self._database
				)
			else:
				mysql_db = MySQLdb.connect(
				 host=self._host, user=self._username, passwd=self._password, db=self._database
				)
			mysql_cur = mysql_db.cursor()
			
			mysql_cur.execute(' '.join((
			 "SELECT m.ip,",
			 "s.gateway, s.subnet_mask, s.broadcast_address, s.domain_name, s.domain_name_servers,",
			 "s.lease_time FROM maps m, subnets s",
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
	_file = None
	
	def __init__(self):
		self._resource_lock = threading.BoundedSemaphore(conf.SQLITE_MAXIMUM_CONNECTIONS)
		
		self._file = conf.SQLITE_FILE
		
	def _lookupMAC(self, mac):
		"""
		May raise exception.
		"""
		try:
			sqlite_db = sqlite3.connect(self._file)
			sqlite_cur = sqlite_db.cursor()
			
			sqlite_cur.execute(' '.join((
			 "SELECT m.ip,",
			 "s.gateway, s.subnet_mask, s.broadcast_address, s.domain_name, s.domain_name_servers,",
			 "s.lease_time FROM maps m, subnets s",
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
				
SQL_BROKER = None
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
	