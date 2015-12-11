#Copy this file to one of the following locations, then rename it to conf.py:
#/etc/staticDHCPd/, ./conf/

#For a full overview of what these parameters mean, and to further customise
#your system, please consult the configuration and scripting guides in the
#standard documentation


# Whether to daemonise on startup (you don't want this during initial setup)
DAEMON = False
DEBUG = True
LOG_FILE_SEVERITY = 'DEBUG'
LOG_CONSOLE_SEVERITY = 'DEBUG'

#WARNING: The default UID and GID are those of root. THIS IS NOT GOOD!
#If testing, set them to your id, which you can find using `id` in a terminal.
#If going into production, if no standard exists in your environment, use the
#values of "nobody": `id nobody`
#The UID this server will use after initial setup
UID = 0
#The GID this server will use after initial setup
GID = 0

ALLOW_DHCP_RELAYS = True
#The IP of the interface to use for DHCP traffic
DHCP_SERVER_IP = '10.244.36.61'

DHCP_RESPONSE_INTERFACE = 'vboxnet0'

MEMCACHED_CACHE = True
MEMCACHED_HOST = '127.0.0.1'

#The database-engine to use
#For details, see the configuration guide in the documentation.
import httpdb
DATABASE_ENGINE = httpdb.HTTPCachingDatabase #or httpdb.HTTPCachingDatabase

X_HTTPDB_ADDITIONAL_INFO = {'datacenter':'ANDOVERQA'}

X_HTTPDB_SERVICE_ADDRESS = '10.244.36.60'
X_HTTPDB_SERVICE_PORT = 8200
X_HTTPDB_URI = 'http://%s:%d/dhcpconfig/' % (X_HTTPDB_SERVICE_ADDRESS, X_HTTPDB_SERVICE_PORT)

X_HTTPDB_DEFAULT_NAME_SERVERS = '8.8.8.8,8.8.4.4'
X_HTTPDB_DEFAULT_LEASE_TIME = 43200
X_HTTPDB_DEFAULT_SERIAL = 0
X_HTTPDB_LOCAL_RELAYS = False

#test = requests.get('http://app-stage:8200/netconfig?datacenter=ANDOVERQA&mac=00:50:56:92:78:46')

handleUnknownMAC = httpdb._handle_unknown_mac
