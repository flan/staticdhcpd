# -*- encoding: utf-8 -*-
"""
staticDHCPd module: src.conf

Purpose
=======
 Provides a buffer to seed options with default values to make upgrading easier
 for end users who do not need to manage any newly added features.
 
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
 
 (C) Neil Tallim, 2011 <red.hamsterx@gmail.com>
"""
import conf

#Inject namespace elements into conf.
##############################################################################
import dhcp
conf.ipToList = dhcp.ipToList
conf.ipsToList = dhcp.ipsToList
conf.intToList = dhcp.intToList
conf.intsToList = dhcp.intsToList
conf.longToList = dhcp.longToList
conf.longsToList = dhcp.longsToList
conf.strToList = dhcp.strToList
conf.rfc3046_decode = dhcp.rfc3046_decode
del dhcp

import libpydhcpserver.type_rfc as type_rfc
conf.rfc2610_78 = type_rfc.rfc2610_78
conf.rfc2610_79 = type_rfc.rfc2610_79
conf.rfc3361_120 = type_rfc.rfc3361_120
conf.rfc3397_119 = type_rfc.rfc3397_119
conf.rfc3925_124 = type_rfc.rfc3925_124
conf.rfc3925_125 = type_rfc.rfc3925_125
conf.rfc4174_83 = type_rfc.rfc4174_83
conf.rfc4280_88 = type_rfc.rfc4280_88
conf.rfc5223_137 = type_rfc.rfc5223_137
conf.rfc5678_139 = type_rfc.rfc5678_139
conf.rfc5678_140 = type_rfc.rfc5678_140
del type_rfc

import logging
conf.writeLog = logging.writeLog
del logging


#Options passed through from conf.py
#For explanations, please consult that file.
##############################################################################
_defaults = {}

#General settings
#######################################
_defaults.update({
 'DEBUG': False,
 
 'SYSTEM_NAME': 'staticDHCPd',
})
_defaults.update({
 'LOG_FILE': '/var/log/' + _defaults['SYSTEM_NAME'] + '.log',
 'LOG_FILE_TIMESTAMP': False,
 'PID_FILE': '/var/run/' + _defaults['SYSTEM_NAME'] + '.pid',
 
 'POLLING_INTERVAL': 30,
 'LOG_CAPACITY': 1000,
 'POLL_INTERVALS_TO_TRACK': 20,
})

#Server settings
#######################################
_defaults.update({
 'UID': 99,
 'GID': 99,

 'DHCP_SERVER_IP': '192.168.1.100',
 'DHCP_SERVER_PORT': 67,
 'DHCP_CLIENT_PORT': 68,

 'PXE_PORT': None,
 
 'WEB_ENABLED': True,
 'WEB_IP': '192.168.1.100',
 'WEB_PORT': 30880,
})

#Server behaviour settings
#######################################
_defaults.update({
 'ALLOW_LOCAL_DHCP': True,
 'ALLOW_DHCP_RELAYS': False,
 'ALLOWED_DHCP_RELAYS': (),

 'AUTHORITATIVE': False,

 'NAK_RENEWALS': False,

 'UNAUTHORIZED_CLIENT_TIMEOUT': 60,
 'MISBEHAVING_CLIENT_TIMEOUT': 150,
 'ENABLE_SUSPEND': True,
 'SUSPEND_THRESHOLD': 10,

 'WEB_RELOAD_KEY': '5f4dcc3b5aa765d61d8327deb882cf99',
})

#Database settings
#######################################
_defaults.update({
 'DATABASE_ENGINE': 'MySQL',

 'USE_CACHE': False,

 'USE_POOL': True,

 'MYSQL_DATABASE': 'dhcp',
 'MYSQL_USERNAME': 'dhcp_user',
 'MYSQL_PASSWORD': 'dhcp_pass',
 'MYSQL_HOST': None,
 'MYSQL_PORT': 3306,
 'MYSQL_MAXIMUM_CONNECTIONS': 4,

 'POSTGRESQL_DATABASE': 'dhcp',
 'POSTGRESQL_USERNAME': 'dhcp_user',
 'POSTGRESQL_PASSWORD': 'dhcp_pass',
 'POSTGRESQL_HOST': None,
 'POSTGRESQL_PORT': 5432,
 'POSTGRESQL_SSLMODE': 'disabled',
 'POSTGRESQL_MAXIMUM_CONNECTIONS': 4,

 'ORACLE_DATABASE': 'dhcp',
 'ORACLE_USERNAME': 'dhcp_user',
 'ORACLE_PASSWORD': 'dhcp_pass',
 'ORACLE_MAXIMUM_CONNECTIONS': 4,

 'SQLITE_FILE': '/etc/staticDHCPd/dhcp.sqlite3',
})

#E-mail settings
#######################################
_defaults.update({
 'EMAIL_ENABLED': False,
 'EMAIL_SERVER': 'mail.yourdomain.com',
 'EMAIL_SOURCE': 'you@yourdomain.com',
 'EMAIL_DESTINATION': 'problems@yourdomain.com',
 'EMAIL_USER': 'you',
 'EMAIL_PASSWORD': 'password',
 'EMAIL_TIMEOUT': 600,
})


#Construct a unified namespace
#######################################
for (key, value) in _defaults.iteritems():
    if hasattr(conf, key):
        globals[key] = getattr(conf, key)
    else:
        globals[key] = value
del _defaults

