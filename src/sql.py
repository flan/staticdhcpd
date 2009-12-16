import threading

import conf
#Evaluation occurs at the bottom of this module.

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
			
			mysql_cur.execute("SELECT ip FROM maps WHERE mac = %s LIMIT 1", (mac,))
			result = mysql_cur.fetchone()
			if result:
				return result[0]
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
		self._resource_lock = threading.Lock()
		
		self._file = conf.SQLITE_FILE
		
	def _lookupMAC(self, mac):
		"""
		May raise exception.
		"""
		try:
			sqlite_db = sqlite3.connect(self._file)
			sqlite_cur = sqlite_db.cursor()
			
			sqlite_cur.execute("SELECT ip FROM maps WHERE mac = ? LIMIT 1", (mac,))
			result = sqlite_cur.fetchone()
			if result:
				return result[0]
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
	