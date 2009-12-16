SYSTEM_NAME = 'staticDHCPd'
LOG_CAPACITY = 250 #: The number of events to keep in the server's log-buffer.

DHCP_SERVER_IP = '192.168.0.10' #: The IP of the interface on which DHCP responses should be sent.
SERVER_PORT = 67 #: The port on which DHCP requests are to be received; 67 is the standard.
CLIENT_PORT = 68 #: The port on which clients wait for DHCP responses; 68 is the standard.
UNAUTHORIZED_CLIENT_TIMEOUT = 60 #: The number of seconds for which to ignore unknown MACs.
MISBEHAVING_CLIENT_TIMEOUT = 300 #: The number of seconds for which to ignore potentially malicious MACs.

WEB_ENABLED = True #: True to enable access to server statistics and logs.
WEB_IP = '192.168.1.10' #: The IP of the interface on which the HTTP interface should be served.
WEB_PORT = 30880 #: The port on which the HTTP interface should be served.

#######################################

DATABASE_ENGINE = 'MySQL' #: Allowed values: MySQL, SQLite

MYSQL_DATABASE = 'dhcp' #: The name of your database.
MYSQL_USERNAME = 'dhcp_user' #: The name of a user with SELECT access.
MYSQL_PASSWORD = 'dhcp_pass' #: The password of the user.
MYSQL_HOST = None #: The host on which MySQL is running. None for 'localhost'.
MYSQL_PORT = 3306 #: The port on which MySQL is running; ignored when HOST is None.

SQLITE_FILE = '/etc/staticDHCPd/dhcp.sqlite3' #: The file that contains your SQLite database.
