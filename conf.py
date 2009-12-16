#General settings
#####
#Changes take effect on reload
#######################################
SYSTEM_NAME = 'staticDHCPd'
LOG_FILE = '/Users/admin/' + SYSTEM_NAME + '.log' #: The file to which logs should be dumped on receipt of TERM or HUP.

LOG_CAPACITY = 1000 #: The number of events to keep in the server's log-buffer.
POLL_INTERVALS_TO_TRACK = 20 #: The amount of stats to keep track of.

#Server settings
#####
#Changes take effect on restart
#######################################
UID = 502 #The UID that will run this daemon.
GID = 99 #The GID that will run this daemon.
PID_FILE = '/Users/admin/' + SYSTEM_NAME + '.pid' #: The file to which PID information should be written.

DHCP_SERVER_IP = '192.168.1.2' #The IP of the interface on which DHCP responses should be sent.
DHCP_SERVER_PORT = 67 #: The port on which DHCP requests are to be received; 67 is the standard.
DHCP_CLIENT_PORT = 68 #: The port on which clients wait for DHCP responses; 68 is the standard.
UNAUTHORIZED_CLIENT_TIMEOUT = 60 #The number of seconds for which to ignore unknown MACs.
MISBEHAVING_CLIENT_TIMEOUT = 300 #The number of seconds for which to ignore potentially malicious
#MACs.

WEB_ENABLED = True #: True to enable access to server statistics and logs.
WEB_IP = '192.168.1.2' #: The IP of the interface on which the HTTP interface should be served.
WEB_PORT = 30880 #: The port on which the HTTP interface should be served.
WEB_RELOAD_KEY = 'fe07c43ee3f1ce1cb0c5eadb9b608151' #: MD5 hash of the password needed to reload config.

#Server behaviour settings
#####
#Changes take effect on reload
#######################################
ALLOW_DHCP_RELAYS = True #: If False, relayed DHCP requests will be ignored.
ALLOWED_DHCP_RELAYS = () #: A list of all IPs allowed to relay requests; if empty, all are allowed.
#(End with trailing comma)
ALLOW_DHCP_RENEW = False #: If True, DHCP clients may renew their "lease" before it expires.
#Since there are no leases, this setting makes no real difference.
NAK_RENEWALS = True #: If True, REBIND and RENEW requests are NAKed when received, forcing clients
#to either wait out their lease or return to the DISCOVER phase.
POLLING_INTERVAL = 30 #: The frequency at which the DHCP server's stats will be polled.
SUSPEND_THRESHOLD = 8 #: The number of times a well-behaved MAC can search for or request an IP
#within the polling interval.

#Database settings
#####
#Changes take effect on restart
#######################################
DATABASE_ENGINE = 'MySQL' #: Allowed values: MySQL, SQLite

MYSQL_DATABASE = 'dhcp' #: The name of your database.
MYSQL_USERNAME = 'dhcp_user' #: The name of a user with SELECT access.
MYSQL_PASSWORD = 'dhcp_pass' #: The password of the user.
MYSQL_HOST = None #: The host on which MySQL is running. None for 'localhost'.
MYSQL_PORT = 3306 #: The port on which MySQL is running; ignored when HOST is None.
MYSQL_MAXIMUM_CONNECTIONS = 4 #: The number of threads that may read the database at once.

SQLITE_FILE = '/etc/staticDHCPd/dhcp.sqlite3' #: The file that contains your SQLite database.

#DHCP-processing functions
#####
#Changes take effect on reload
#######################################
#DO NOT TOUCH LINES BELOW THIS POINT
import pydhcplib.type_strlist
#DO NOT TOUCH LINES ABOVE THIS POINT

def loadDHCPPacket(packet, client_ip, relay_ip):
	"""
	If you do not need an option, just comment it out.
	
	If you need to add an option, consult pyDHCPlib's documentation.
	
	client_ip is a quadruple of octets.
	relay_ip is either None or an address as a quadruple of octets,
		depending on whether this is a response to a relay request.
	"""
	pass
	