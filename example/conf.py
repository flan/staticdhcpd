#Copy this file to one of the following locations, then rename it to conf.py:
#/etc/staticDHCPd/, ./conf/

#For a full overview of what these parameters mean, and to further customise
#your system, please consult the configuration and scripting guides in the
#standard documentation


# Whether to daemonise on startup (you don't want this during initial setup)
DAEMON = False
#DAEMON = True

#WARNING: The default UID and GID are those of root. THIS IS NOT GOOD!
#If testing, set them to your id, which you can find using `id` in a terminal.
#If going into production, if no standard exists in your environment, use the
#values of "nobody": `id nobody`
#The UID this server will use after initial setup
#UID = 0
UID = 0
#The GID this server will use after initial setup
#GID = 0
GID = 0

#The IP of the interface to use for DHCP traffic
DHCP_SERVER_IP = '172.16.201.3'

#The database-engine to use
#For details, see the configuration guide in the documentation.
DATABASE_ENGINE = 'SQLite'
SQLITE_FILE = '/etc/staticDHCPd/dhcp.sqlite3'

