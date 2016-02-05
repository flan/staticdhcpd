# -*- encoding: utf-8 -*-
"""
staticdhcpdlib.config
=====================
Provides a buffer to seed options with default values to make upgrading easier
for end users who do not need to manage any newly added features.

Also handles the process of determining where config values should be accessed.

WARNING
-------
If you are attempting to customise your environment, edit conf.py instead.
If testing, it will likely be in conf/; if installed, in /etc/staticDHCPd/;
or, if upgrading from an older version, in the same directory as main.py.

This file is intended for internal use only and modifications here will
probably lead to headaches later.

Legal
-----
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

(C) Neil Tallim, 2014 <flan@uguu.ca>
"""
#Get the "conf" module from somewhere
conf = None
import os
import sys
import imp

if 'STATICDHCPD_CONF_PATH' in os.environ:
    conf_search_paths = [os.path.dirname(os.environ['STATICDHCPD_CONF_PATH'])]
else:
    conf_search_paths = [os.path.join(os.getcwd(), 'conf'), '/etc/staticDHCPd']

for conf_path in conf_search_paths:
    extensions_path = os.path.join(conf_path, 'extensions')
    sys.path.append(conf_path)
    sys.path.append(extensions_path)
    try: #Attempt to import conf.py from the path
        conf = imp.load_source('conf', os.path.join(conf_path, 'conf.py'))
    except IOError:
        sys.path.remove(conf_path)
        sys.path.remove(extensions_path)
    else:
        break
else:
    raise ImportError("Unable to find a suitable copy of conf.py; searched: %(paths)r" % {
     'paths': conf_search_paths,
    })

del conf_search_paths
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
 'DHCP_RESPONSE_INTERFACE': '-',
 'DHCP_RESPONSE_INTERFACE_QTAGS': None,
 'DHCP_SERVER_PORT': 67,
 'DHCP_CLIENT_PORT': 68,
 'PROXY_PORT': None,
})

#Database settings
#######################################
_defaults.update({
 'USE_CACHE': False,
 'CACHING_MODEL': 'in-process',

 'PERSISTENT_CACHE': None,
 'CACHE_ON_DISK': False,

 'MEMCACHED_HOST': None,
 'MEMCACHED_PORT': 11211,
 'MEMCACHED_AGE_TIME': 300, #5 minutes

 'CASE_INSENSITIVE_MACS': False,

 'EXTRA_MAPS': None,
 'EXTRA_SUBNETS': None,

 'USE_POOL': True,

 'POSTGRESQL_HOST': None,
 'POSTGRESQL_PORT': 5432,
 'POSTGRESQL_SSLMODE': 'disable',
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
 'ENABLE_RAPIDCOMMIT': True,

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
 'WEB_REINITIALISE_HIDDEN': False,
 'WEB_REINITIALISE_ENABLED': True,
 'WEB_DASHBOARD_ORDER_LOG': 1000,
 'WEB_HEADER_TITLE': True,
 'WEB_HEADER_CSS': True,
 'WEB_HEADER_FAVICON': True,
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

#Bind known functions and handle backwards-compatibility
#######################################
#PXE_PORT was renamed to PROXY_PORT because its role was misunderstood
if 'PXE_PORT' in globals() and 'PROXY_PORT' not in globals():
    PROXY_PORT = PXE_PORT

import inspect
if hasattr(conf, 'init'):
    init = conf.init
else:
    init = lambda *args, **kwargs : None
if hasattr(conf, 'filterPacket'):
    filterPacket = conf.filterPacket
else:
    filterPacket = lambda *args, **kwargs : True

if hasattr(conf, 'handleUnknownMAC'):
    if inspect.getargspec(conf.handleUnknownMAC).args == ['mac']:
        #It's pre-2.0.0, so wrap it for backwards-compatibility
        handleUnknownMAC = (
         lambda packet, method, mac, client_ip, relay_ip, port:
            conf.handleUnknownMAC(mac)
        )
    else:
        handleUnknownMAC = conf.handleUnknownMAC
else:
    handleUnknownMAC = lambda *args, **kwargs : None

if hasattr(conf, 'filterRetrievedDefinitions'):
    filterRetrievedDefinitions = conf.filterRetrievedDefinitions
else:
    def filterRetrievedDefinitions(definitions, *args, **kwargs):
        raise ValueError('No handler exists for multi-definition matches; implement filterRetrievedDefinitions()')

if hasattr(conf, 'loadDHCPPacket'):
    if inspect.getargspec(conf.loadDHCPPacket).args == ['packet', 'mac', 'client_ip', 'relay_ip', 'subnet', 'serial', 'pxe', 'vendor']:
        #It's pre-2.0.0, so wrap it for backwards-compatibility
        import collections
        __PXEOptions = collections.namedtuple("PXEOptions", (
            'client_system', 'client_ndi', 'uuid_guid'
        ))
        del collections
        
        def loadDHCPPacket(packet, method, mac, definition, relay_ip, port, source_packet):
            vendor_class = None
            if source_packet.isOption('vendor_class'):
                vendor_class = tuple(sorted(source_packet.getOption('vendor_class', convert=True).items()))
            if source_packet.isOption('vendor_class_identifier'):
                vendor_class_identifier = tuple((k, tuple(sorted(v.items()))) for (k, v) in sorted(source_packet.getOption('vendor_specific', convert=True).items()))
                
            pxe_options = None
            if port == PROXY_PORT:
                option_93 = source_packet.getOption(93, convert=True) #client_system
                option_94 = source_packet.getOption(94) #client_ndi
                option_97 = source_packet.getOption(97) #uuid_guid
                pxe_options = __PXEOptions(
                    option_93,
                    option_94 and tuple(option_94),
                    option_97 and (option_97[0], option_97[1:])
                )
                
            return conf.loadDHCPPacket(
                packet, mac, definition.ip, relay_ip, definition.subnet, definition.serial,
                pxe_options,
                (
                    source_packet.getOption('vendor_specific_information'),
                    source_packet.getOption('vendor_class_identifier', convert=True),
                    vendor_class,
                    vendor_class_identifier,
                ),
            )
    else:
        loadDHCPPacket = conf.loadDHCPPacket
else:
    loadDHCPPacket = lambda *args, **kwargs : True
del inspect

#Inject namespace elements into conf.
##############################################################################
import libpydhcpserver.dhcp_types.conversion as conversion
conf.listToIP = conversion.listToIP
conf.listToIPs = conversion.listToIPs
conf.ipToList = conversion.ipToList
conf.ipsToList = conversion.ipsToList
conf.listToInt = conversion.listToInt
conf.listToInts = conversion.listToInts
conf.listToLong = conversion.listToLong
conf.listToLongs = conversion.listToLongs
conf.intToList = conversion.intToList
conf.intsToList = conversion.intsToList
conf.longToList = conversion.longToList
conf.longsToList = conversion.longsToList
conf.strToList = conversion.strToList
conf.strToPaddedList = conversion.strToPaddedList
conf.listToStr = conversion.listToStr
del conversion

import libpydhcpserver.dhcp_types.rfc as rfc
conf.rfc3046_decode = rfc.rfc3046_decode
conf.rfc3925_decode = rfc.rfc3925_decode
conf.rfc3925_125_decode = rfc.rfc3925_125_decode
conf.rfc1035_plus = rfc.rfc1035_plus
conf.rfc2610_78 = rfc.rfc2610_78
conf.rfc2610_79 = rfc.rfc2610_79
conf.rfc3361_120 = rfc.rfc3361_120
conf.rfc3397_119 = rfc.rfc3397_119
conf.rfc3442_121 = rfc.rfc3442_121
conf.rfc3925_124 = rfc.rfc3925_124
conf.rfc3925_125 = rfc.rfc3925_125
conf.rfc4174_83 = rfc.rfc4174_83
conf.rfc4280_88 = rfc.rfc4280_88
conf.rfc5223_137 = rfc.rfc5223_137
conf.rfc5678_139 = rfc.rfc5678_139
conf.rfc5678_140 = rfc.rfc5678_140
del rfc

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
    """
    A data-namespace, used to isolate callback-management functions.
    """
    systemAddReinitHandler = staticmethod(system.registerReinitialisationCallback)
    systemRemoveReinitHandler = staticmethod(system.unregisterReinitialisationCallback)
    systemAddTickHandler = staticmethod(system.registerTickCallback)
    systemRemoveTickHandler = system.unregisterTickCallback

    statsAddHandler = staticmethod(statistics.registerStatsCallback)
    statsRemoveHandler = statistics.unregisterStatsCallback

    WEB_METHOD_DASHBOARD = web.WEB_METHOD_DASHBOARD
    WEB_METHOD_TEMPLATE = web.WEB_METHOD_TEMPLATE
    WEB_METHOD_RAW = web.WEB_METHOD_RAW
    webAddHeader = staticmethod(web.registerHeaderCallback)
    webRemoveHeader = staticmethod(web.unregisterHeaderCallback)
    webAddDashboard = staticmethod(web.registerDashboardCallback)
    webRemoveDashboard = staticmethod(web.unregisterDashboardCallback)
    webAddMethod = staticmethod(web.registerMethodCallback)
    webRemoveMethod = staticmethod(web.unregisterMethodCallback)
del system
del statistics
del web
conf.callbacks = callbacks

class _Namespace(object):
    """
    A data-namespace, used to centralise extensions-configuration values.
    """
    __final = False #: If True, then no new layers will be created

    def __init__(self, final=False):
        """
        :param bool final: ``False`` if new namespaces may be automatically
                           created beneath this one.
        """
        self.__final = final

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        return False

    def __getattr__(self, name):
        if name.startswith('__'):
            return object.__getattr__(self, name)

        if self.__final:
            raise AttributeError("Namespace does not contain '%(name)s'" % {
                'name': name,
            })
        namespace = self.__class__(final=True)
        object.__setattr__(self, name, namespace)
        return namespace

    def extension_config_iter(self):
        """
        Produces an iterable object that enumerates all interesting elements in
        the namespace.

        :return: An iterable object that generates ``(key, value)`` tuples.
        """
        for key in [k for k in dir(self) if not k.startswith('_') and not k.startswith('extension_config_')]: #Copy everything that looks useful
            yield (key, getattr(self, key))

    def extension_config_dict(self):
        """
        Produces a dictionary containing all interesting elements in the
        namespace.

        :return dict: User-set elements in the namespace.
        """
        return dict(self.extension_config_iter())

    def extension_config_merge(self, defaults, required):
        """
        Creates a namespace model from `defaults` before overlaying anything
        defined in this namespace instance, then ensuring that all required
        attributes exist.

        Normal usage will be something like the following::

            CONFIG = this_object.extension_config_merge(defaults={
                'DEFAULT_THING': 5, #Your description of this field
            }, required=[
                'REQUIRED_THING', #Your description (with typing) of what this field means
            ])

        This is effectively self-documenting and it guarantees you'll have
        access to every attribute you want.

        :param dict defaults: The default attributes for the namespace, if not
                              already present.
        :param collection required: A collection of required attribute names.
        :return dict: `defaults` augmented with elements defined in the
                      namespace, then validated to ensure all ``required``
                      elements are present in some form.
        :raise AttributeError: A required attribute is missing.
        :raise ValueError: The namespace cannot be merged.
        """
        if not self.__final:
            raise ValueError("Unable to merge a non-final namespace")

        namespace = defaults.copy()
        namespace.update(self.extension_config_iter())
        for key in required:
            if not key in namespace:
                raise AttributeError("Merged result does not contain '%(key)s'" % {
                    'key': key,
                })
        return namespace
conf.extensions = _Namespace()
