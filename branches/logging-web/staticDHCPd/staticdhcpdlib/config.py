# -*- encoding: utf-8 -*-
"""
staticDHCPd module: config

WARNING
=======
 If you are attempting to customise your environment, edit conf.py instead.
 If testing, it will likely be in conf/, if installed, in /etc/staticDHCPd/,
 or, if upgrading from an older version, in the same directory as main.py.
 
 This file is intended for internal use only and modifications here will
 probably lead to headaches later.

Purpose
=======
 Provides a buffer to seed options with default values to make upgrading easier
 for end users who do not need to manage any newly added features.
 
 Also handles the process of determining where config values should be accessed.
 
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
 
 (C) Neil Tallim, 2013 <flan@uguu.ca>
"""
#Get the "conf" module from somewhere
conf = None
import os
import sys
import imp
conf_path = os.path.join(os.getcwd(), 'conf')
sys.path.append(conf_path)
try: #Look for a 'conf/' subdirectory
    conf = imp.load_source('conf', os.path.join(conf_path, 'conf.py'))
except IOError:
    sys.path.remove(conf_path)
    
    etc_path = '/etc/staticDHCPd'
    sys.path.append(etc_path)
    try: #If that fails, try /etc/staticDHCPd/
        conf = imp.load_source('conf', os.path.join(etc_path, 'conf.py'))
    except IOError:
        sys.path.remove(etc_path)
        
        raise ImportError("Unable to find a suitable copy of conf.py")
    finally:
        del etc_path
finally:
    del conf_path
    del os
    del sys
    del imp
    
#Options passed through from conf.py
#For explanations, please consult that file.
##############################################################################
_defaults = {}

#General settings
#######################################
_defaults.update({
 'DEBUG': False,
 'DAEMON': True,
 'SYSTEM_NAME': 'staticDHCPd',
 'PID_FILE': None,
})

#Server settings
#######################################
_defaults.update({
 'PXE_PORT': None,
})

#Database settings
#######################################
_defaults.update({
 'USE_CACHE': False,

 'USE_POOL': True,

 'POSTGRESQL_HOST': None,
 'POSTGRESQL_PORT': 5432,
 'POSTGRESQL_SSLMODE': 'disabled',
 'POSTGRESQL_MAXIMUM_CONNECTIONS': 4,

 'ORACLE_MAXIMUM_CONNECTIONS': 4,
 
 'MYSQL_HOST': None,
 'MYSQL_PORT': 3306,
 'MYSQL_MAXIMUM_CONNECTIONS': 4,
})

#Server behaviour settings
#######################################
_defaults.update({
 'ALLOW_LOCAL_DHCP': True,
 'ALLOW_DHCP_RELAYS': False,
 'ALLOWED_DHCP_RELAYS': [],

 'AUTHORITATIVE': False,
 'NAK_RENEWALS': False,

 'UNAUTHORIZED_CLIENT_TIMEOUT': 60,
 'MISBEHAVING_CLIENT_TIMEOUT': 150,
 'ENABLE_SUSPEND': True,
 'SUSPEND_THRESHOLD': 10,
})

#Logging settings
#######################################
_defaults.update({
 'LOG_FILE': None,
 'LOG_FILE_HISTORY': 7,
 'LOG_FILE_SEVERITY': 'WARN',
 'LOG_CONSOLE_SEVERITY': 'INFO',
})

#Webservice settings
#######################################
_defaults.update({
 'WEB_ENABLED': True,
 'WEB_IP': '0.0.0.0',
 'WEB_PORT': 30880,
 'WEB_LOG_HISTORY': 200,
 'WEB_LOG_SEVERITY': 'INFO',
 'WEB_LOG_MAX_HEIGHT': 400,
 'WEB_DIGEST_USERNAME': None,
 'WEB_DIGEST_PASSWORD': None,
 'WEB_DASHBOARD_SECURE': False,
 'WEB_REINITIALISE_CONFIRM': True,
 'WEB_REINITIALISE_SECURE': False,
 'WEB_DASHBOARD_ORDER_LOG': 1000,
})

#Statistics settings
#######################################
_defaults.update({
 'STATS_ENABLED': True,
 'STATS_QUANTISATION': 60 * 5,
 'STATS_RETENTION_COUNT': 288 * 2,
})

#E-mail settings
#######################################
_defaults.update({
 'EMAIL_ENABLED': False,
 'EMAIL_PORT': 25,
 'EMAIL_TIMEOUT': 4.0,
 'EMAIL_SUBJECT': "staticDHCPd encountered a problem",
 'EMAIL_USER': None,
})


#Construct a unified namespace
#######################################
for key in [k for k in dir(conf) if k.isupper()]: #Copy everything that looks like a constant.
    globals()[key] = getattr(conf, key)

for (key, value) in _defaults.iteritems():
    if not key in globals():
        globals()[key] = value
del _defaults

import inspect
if hasattr(conf, 'init'):
    init = conf.init
else:
    init = lambda *args, **kwargs : None
if hasattr(conf, 'filterPacket'):
    init = conf.filterPacket
else:
    init = lambda *args, **kwargs : None
if hasattr(conf, 'handleUnknownMAC'):
    if inspect.getargspec(conf.handleUnknownMAC).args == ['mac']:
        #It's pre-2.0.0, so wrap it for backwards-compatibility
        handleUnknownMAC = lambda packet, method, mac, client_ip, relay_ip, pxe, vendor : conf.handleUnknownMAC(mac)
    else:
        handleUnknownMAC = conf.handleUnknownMAC
else:
    handleUnknownMAC = lambda *args, **kwargs : None
if hasattr(conf, 'loadDHCPPacket'):
    if inspect.getargspec(conf.handleUnknownMAC).args == ['packet', 'mac', 'client_ip', 'relay_ip', 'subnet', 'serial', 'pxe', 'vendor']:
        #It's pre-2.0.0, so wrap it for backwards-compatibility
        loadDHCPPacket = lambda packet, method, mac, client_ip, relay_ip, subnet, serial, pxe, vendor : conf.loadDHCPPacket(packet, mac, subnet, serial, client_ip, relay_ip, pxe, vendor)
    else:
        loadDHCPPacket = conf.loadDHCPPacket
else:
    loadDHCPPacket = lambda *args, **kwargs : True
del inspect

#Inject namespace elements into conf.
##############################################################################
import libpydhcpserver.type_rfc as type_rfc
conf.rfc3046_decode = type_rfc.rfc3046_decode
conf.rfc1035_plus = type_rfc.rfc1035_plus

conf.ipToList = type_rfc.ipToList
conf.ipsToList = type_rfc.ipsToList
conf.intToList = type_rfc.intToList
conf.intsToList = type_rfc.intsToList
conf.longToList = type_rfc.longToList
conf.longsToList = type_rfc.longsToList
conf.strToList = type_rfc.strToList
conf.strToPaddedList = type_rfc.strToPaddedList

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
logger = logging.getLogger('conf')
conf.writeLog = logger.warn
conf.logger = logger
del logger
del logging

import system
import statistics
import web
class callbacks(object):
    systemAddReinitHandler = staticmethod(system.registerReinitialisationCallback)
    systemRemoveReinitHandler = staticmethod(system.unregisterReinitialisationCallback)
    systemAddTickHandler = staticmethod(system.registerTickCallback)
    systemRemoveTickHandler = system.unregisterTickCallback
    
    statsAddHandler = staticmethod(statistics.registerStatsCallback)
    statsRemoveHandler = statistics.unregisterStatsCallback
    
    WEB_METHOD_DASHBOARD = web.WEB_METHOD_DASHBOARD
    WEB_METHOD_TEMPLATE = web.WEB_METHOD_TEMPLATE
    WEB_METHOD_RAW = web.WEB_METHOD_RAW
    webAddDashboard = staticmethod(web.registerDashboardCallback)
    webRemoveDashboard = staticmethod(web.unregisterDashboardCallback)
    webAddMethod = staticmethod(web.registerMethodCallback)
    webRemoveMethod = staticmethod(web.unregisterMethodCallback)
del system
del statistics
del web
conf.callbacks = callbacks