import MySQLdb

class SQL(object):
	_host = None
	_username = None
	_password = None
	_database = None
	
	def __init__(self, host, username, password, database):
		self._host = host
		self._username = username
		self._password = password
		self._database = database
		
	def lookupMAC(self, mac):
		"""
		May raise exception.
		"""
		try:
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
				