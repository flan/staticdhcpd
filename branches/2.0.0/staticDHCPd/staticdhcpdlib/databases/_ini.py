# -*- encoding: utf-8 -*-
"""
staticDHCPd module: databases._ini

Purpose
=======
 Provides a uniform datasource API, implementing an INI-file-based backend.
 
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
 Inspiration derived from a discussion with John Stowers
"""
import ConfigParser
import logging
import re
import threading

from libpydhcpserver.dhcp_types.mac import MAC

from .. import config

from generic import (Definition, Database)

_logger = logging.getLogger("databases._ini")

class _Config(ConfigParser.RawConfigParser):
    """
    A simple wrapper around RawConfigParser to extend it with support for default values.
    """
    def get(self, section, option, default):
        """
        Returns a custom value, if one is found. Otherwise, returns C{default}.
        
        @type section: basestring
        @param section: The section to be queried.
        @type option: basestring
        @param option: The option to be queried.
        @type default: object
        @param default: The value to be returned, if the requested option is undefined.
        
        @rtype: object
        @return: Either the requested value or the given default.
        """
        try:
            return ConfigParser.RawConfigParser.get(self, section, option)
        except ConfigParser.Error:
            return default
            
    def getint(self, section, option, default):
        """
        Returns a custom value, if one is found. Otherwise, returns C{default}.
        
        @type section: basestring
        @param section: The section to be queried.
        @type option: basestring
        @param option: The option to be queried.
        @type default: int
        @param default: The value to be returned, if the requested option is undefined.
        
        @rtype: int
        @return: Either the requested value or the given default.
        
        @raise ValueError: The value to be returned could not be converted to an C{int}.
        """
        return int(self.get(section, option, default))
        
    def getfloat(self, section, option, default):
        """
        Returns a custom value, if one is found. Otherwise, returns C{default}.
        
        @type section: basestring
        @param section: The section to be queried.
        @type option: basestring
        @param option: The option to be queried.
        @type default: float
        @param default: The value to be returned, if the requested option is undefined.
        
        @rtype: float
        @return: Either the requested value or the given default.
        
        @raise ValueError: The value to be returned could not be converted to a C{float}.
        """
        return float(self.get(section, option, default))
        
    def getboolean(self, section, option, default):
        """
        Returns a custom value, if one is found. Otherwise, returns C{default}.
        
        @type section: basestring
        @param section: The section to be queried.
        @type option: basestring
        @param option: The option to be queried.
        @type default: bool
        @param default: The value to be returned, if the requested option is undefined.
        
        @rtype: bool
        @return: Either the requested value or the given default.
        """
        return bool(str(self.get(section, option, default)).lower().strip() in (
         'y', 'yes',
         't', 'true',
         'ok', 'okay',
         '1',
        ))

class INI(Database):
    """
    Implements an INI broker.
    """
    _maps = None
    _subnets = None
    _lock = None
    
    def __init__(self):
        """
        Constructs the broker.
        """
        self._maps = {}
        self._subnets = {}
        self._lock = threading.Lock()
        
        self.reinitialise()
        
    def reinitialise(self):
        with self._lock:
            self._maps.clear()
            self._subnets.clear()
            self._parse_ini()
        _logger.info("INI-file contents parsed and loaded into memory")
        
    def _parse_ini(self):
        """
        Creates an optimal in-memory representation of the data in the INI file.
        """
        _logger.info("Preparing to read '%(ini)s'..." % {'ini': config.INI_FILE,})
        reader = _Config()
        if not reader.read(config.INI_FILE):
            raise ValueError("Unable to read '%(file)s'" % {
             'file': config.INI_FILE,
            })
            
        subnet_re = re.compile(r"^(?P<subnet>.+?)\|(?P<serial>\d+)$")
        
        for section in reader.sections():
            m = subnet_re.match(section)
            if m:
                self._process_subnet(reader, section, m.group('subnet'), int(m.group('serial')))
            else:
                try:
                    mac = MAC(section)
                except Exception:
                    _logger.warn("Unrecognised section encountered: " + section)
                else:
                    self._process_map(reader, section, mac)
                    
        self._validate_references()
        
    def _process_subnet(self, reader, section, subnet, serial):
        _logger.debug("Processing subnet: " + section)
        
        lease_time = reader.getint(section, 'lease-time', None)
        if not lease_time:
            raise ValueError("Field 'lease-time' unspecified for '%(section)s'" % {
             'section': section,
            })
        gateway = reader.get(section, 'gateway', None)
        subnet_mask = reader.get(section, 'subnet-mask', None)
        broadcast_address = reader.get(section, 'broadcast-address', None)
        ntp_servers = reader.get(section, 'ntp-servers', None)
        domain_name_servers = reader.get(section, 'domain-name-servers', None)
        domain_name = reader.get(section, 'domain-name', None)
        
        self._subnets[(subnet, serial)] = (
         lease_time,
         gateway, subnet_mask, broadcast_address,
         ntp_servers, domain_name_servers, domain_name
        )
        
    def _process_map(self, reader, section, mac):
        _logger.debug("Processing map: " + section)
        
        ip = reader.get(section, 'ip', None)
        if not ip:
            raise ValueError("Field 'ip' unspecified for '%(section)s'" % {
             'section': section,
            })
        hostname = reader.get(section, 'hostname', None)
        subnet = reader.get(section, 'subnet', None)
        if not subnet:
            raise ValueError("Field 'subnet' unspecified for '%(section)s'" % {
             'section': section,
            })
        serial = reader.getint(section, 'serial', None)
        if serial is None:
            raise ValueError("Field 'serial' unspecified for '%(section)s'" % {
             'section': section,
            })
        
        self._maps[str(mac)] = (ip, hostname, (subnet, serial))
        
    def _validate_references(self):
        """
        Effectively performs foreign-key checking, to avoid deferred errors.
        """
        for (mac, (_, _, subnet)) in self._maps.items():
            if subnet not in self._subnets:
                raise ValueError("MAC '%(mac)s' references unknown subnet '%(subnet)s|%(serial)i'" % {
                 'mac': mac,
                 'subnet': subnet[0],
                 'serial': subnet[1],
                })
                
    def lookupMAC(self, mac):
        """
        Queries the database for the given MAC address and returns the IP and
        associated details if the MAC is known.
        
        @type mac: basestring
        @param mac: The MAC address to lookup.
        
        @rtype: Definition|None
        @return: The definition or None, if no match was found.
        
        @raise Exception: If a problem occurs while accessing the database.
        """
        with self._lock:
            map = self._maps.get(str(mac))
            if not map:
                return None
                
            (ip, hostname, subnet) = map
            (lease_time,
            gateway, subnet_mask, broadcast_address,
            ntp_servers, domain_name_servers, domain_name
            ) = self._subnets.get(subnet)
            
        return Definition(
         ip, hostname,
         gateway, subnet_mask, broadcast_address,
         domain_name, domain_name_servers, ntp_servers,
         lease_time, subnet[0], subnet[1]
        )
        
