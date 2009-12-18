#General settings
#####
#Changes take effect on reload
#######################################
SYSTEM_NAME = 'staticDHCPd'
LOG_FILE = '/var/log/' + SYSTEM_NAME + '.log' #The file to which logs should be dumped on receipt of
#TERM or HUP.

POLLING_INTERVAL = 30 #The frequency at which the DHCP server's stats will be polled, in seconds.
LOG_CAPACITY = 1000 #The number of events to keep in the server's log-buffer.
POLL_INTERVALS_TO_TRACK = 20 #The amount of stats to keep track of.

#Server settings
#####
#Changes take effect on restart
#######################################
UID = 999 #The UID that will run this daemon.
GID = 999 #The GID that will run this daemon.
PID_FILE = '/var/run/' + SYSTEM_NAME + '.pid' #The file to which PID information should be written.

DHCP_SERVER_IP = '192.168.1.100' #The IP of the interface on which DHCP responses should be sent.
DHCP_SERVER_PORT = 67 #The port on which DHCP requests are to be received; 67 is the standard.
DHCP_CLIENT_PORT = 68 #The port on which clients wait for DHCP responses; 68 is the standard.

WEB_ENABLED = True #True to enable access to server statistics and logs.
WEB_IP = '192.168.1.100' #The IP of the interface on which the HTTP interface should be served.
WEB_PORT = 30880 #The port on which the HTTP interface should be served.

#Server behaviour settings
#####
#Changes take effect on reload
#######################################
ALLOW_LOCAL_DHCP = True #: If False, local DHCP requests will be ignored.
ALLOW_DHCP_RELAYS = False #If False, relayed DHCP requests will be ignored.
ALLOWED_DHCP_RELAYS = () #A list of all IPs allowed to relay requests; if empty, all are allowed.
#(End with trailing comma)

NAK_RENEWALS = False #If True, REBIND and RENEW requests are NAKed when received, forcing clients to
#either wait out their lease or return to the DISCOVER phase.

UNAUTHORIZED_CLIENT_TIMEOUT = 60 #The number of seconds for which to ignore unknown MACs.
MISBEHAVING_CLIENT_TIMEOUT = 150 #The number of seconds for which to ignore potentially malicious
#MACs.
ENABLE_SUSPEND = True #If True, MACs requesting too many addresses will be flagged as malicious.
SUSPEND_THRESHOLD = 10 #The number of times a well-behaved MAC can search for or request an IP
#within the polling interval.

WEB_RELOAD_KEY = '5f4dcc3b5aa765d61d8327deb882cf99' #MD5 of the password needed to reload config.

#Database settings
#####
#Changes take effect on restart
#######################################
DATABASE_ENGINE = 'MySQL' #Allowed values: MySQL, SQLite

MYSQL_DATABASE = 'dhcp' #The name of your database.
MYSQL_USERNAME = 'dhcp_user' #The name of a user with SELECT access.
MYSQL_PASSWORD = 'dhcp_pass' #The password of the user.
MYSQL_HOST = None #The host on which MySQL is running. None for 'localhost'.
MYSQL_PORT = 3306 #The port on which MySQL is running; ignored when HOST is None.
MYSQL_MAXIMUM_CONNECTIONS = 4 #The number of threads that may read the database at once.

SQLITE_FILE = '/etc/staticDHCPd/dhcp.sqlite3' #The file that contains your SQLite database.
SQLITE_MAXIMUM_CONNECTIONS = 5 #The number of threads that may read the database at once.

#E-mail settings
#####
#Changes take effect on reload
#######################################
EMAIL_ENABLED = False #True to allow staticDHCPd to inform you of any problems it cannot handle by
#itself.
EMAIL_SERVER = 'mail.yourdomain.com' #The server that receives your e-mail.
EMAIL_SOURCE = 'you@yourdomain.com' #The user from which e-mail should claim to be sent.
EMAIL_DESTINATION = 'problems@yourdomain.com' #The user to whom e-mail should be sent.
EMAIL_USER = 'you' #The user who should authenticate to the mail server.
EMAIL_PASSWORD = 'password' #The password of the user who should authenticate to the mail server.

#DHCP-processing functions
#####
#Changes take effect on reload
#######################################
#IMPORT REQUIRED MODULES BELOW THIS LINE
#IMPORT REQUIRED MODULES ABOVE THIS LINE

def loadDHCPPacket(packet, mac, client_ip, relay_ip):
	#This is a custom function, called before each packet is sent, that
	#allows you to tweak the options attached to a DHCP response.
	#
	#If, for any reason, you want to abort sending the packet, return False.
	#
	#If you do not need an option, just comment it out.
	#
	#If you need to add an option, consult pyDHCPlib's documentation.
	#
	#mac is a human-readable MAC string, lower-case, separated by colons.
	#client_ip is a quadruple of octets.
	#relay_ip is either None or an address as a quadruple of octets,
	#	depending on whether this is a response to a relay request.
	return True
	