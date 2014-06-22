# -*- encoding: utf-8 -*-
"""
staticdhcpdlib.databases._ini
=============================
Provides a uniform datasource API, implementing an INI-file-based backend.
 
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
        Returns a custom value, if one is found. Otherwise, returns ``default``.
        
        :param basestring section: The section to be queried.
        :param basestring option: The option to be queried.
        :param basestring default: The value to be returned, if the requested
                                   option is undefined.
        :return basestring : Either the requested value or the given default.
        """
        try:
            return ConfigParser.RawConfigParser.get(self, section, option)
        except ConfigParser.Error:
            return default
            
    def getint(self, section, option, default):
        """
        Returns a custom value, if one is found. Otherwise, returns ``default``.
        
        :param basestring section: The section to be queried.
        :param basestring option: The option to be queried.
        :param int default: The value to be returned, if the requested option
                            is undefined.
        :return int: Either the requested value or the given default.
        :except ValueError: The value to be returned could not be converted to
                            an ``int``.
        """
        return int(self.get(section, option, default))
        
    def getfloat(self, section, option, default):
        """
        Returns a custom value, if one is found. Otherwise, returns ``default``.
        
        :param basestring section: The section to be queried.
        :param basestring option: The option to be queried.
        :param float default: The value to be returned, if the requested
                              option is undefined.
        :return float: Either the requested value or the given default.
        :except ValueError: The value to be returned could not be converted to
                            a ``float``.
        """
        return float(self.get(section, option, default))
        
    def getboolean(self, section, option, default):
        """
        Returns a custom value, if one is found. Otherwise, returns ``default``.
        
        :param basestring section: The section to be queried.
        :param basestring option: The option to be queried.
        :param bool default: The value to be returned, if the requested option
                             is undefined.
        :return bool: Either the requested value or the given default.
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
    _maps = None #: A dictionary of MAC-associations
    _subnets = None #: A dictionary of subnet/serial associations
    _lock = None #: A lock to avoid race-conditions
    
    def __init__(self):
        """
        Constructs the broker.
        """
        self._maps = {}
        self._subnets = {}
        self._lock = threading.Lock()
        
        self.reinitialise()
        
    def _parse_extra_option(self, reader, section, option):
        method = reader.get
        none_on_error = False
        if option[1] == ':':
            l_option = option[0].lower()
            none_on_error = l_option != option[0]
            if l_option == 's':
                pass
            elif l_option == 'i':
                method = reader.getint
            elif l_option == 'f':
                method = reader.getfloat
            elif l_option == 'b':
                method = reader.getboolean
                
        real_option = option[2:]
        try:
            value = method(section, option, None)
        except ValueError:
            if none_on_error:
                return (real_option, None)
            raise
        else:
            return (real_option, value)
            
    def _parse_extra(self, reader, section, omitted, section_type):
        extra = {}
        for option in reader.options(section):
            if not option in omitted:
                (option, value) = self._parse_extra_option(section, option)
                extra['%s.%s' % (section_type, option)] = value
        return extra or None
        
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
        
        extra = self._parse_extra(reader, section, (
         'lease-time', 'gateway', 'subnet-mask', 'broadcast-address',
         'ntp-servers', 'domain-name-servers', 'domain-name',
        ), 'subnets')
        
        self._subnets[(subnet, serial)] = (
         lease_time,
         gateway, subnet_mask, broadcast_address,
         ntp_servers, domain_name_servers, domain_name,
         extra
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
            
        extra = self._parse_extra(reader, section, (
         'ip', 'hostname',
         'subnet', 'serial',
        ), 'maps')
        
        self._maps[int(mac)] = (ip, hostname, (subnet, serial), extra)
        
    def _validate_references(self):
        """
        Effectively performs foreign-key checking, to avoid deferred errors.
        """
        for (mac, (_, _, subnet)) in self._maps.items():
            if subnet not in self._subnets:
                raise ValueError("MAC '%(mac)s' references unknown subnet '%(subnet)s|%(serial)i'" % {
                 'mac': MAC(mac),
                 'subnet': subnet[0],
                 'serial': subnet[1],
                })
                
    def lookupMAC(self, mac):
        mac = int(mac)
        with self._lock:
            map = self._maps.get(mac)
            if not map:
                return None
            subnet = self._subnets.get(map[2])
            
        extra_map = map[3]
        extra_subnet = map[7]
        if extra_map and extra_subnet:
            extra = extra_map.copy()
            extra.update(extra_subnet)
        else:
            extra = (extra_map and extra_map.copy()) or (extra_subnet and extra_subnet.copy())
            
        return Definition(
         ip=map[0], lease_time=subnet[0], subnet=map[2][0], serial=map[2][1],
         hostname=map[1],
         gateway=subnet[1], subnet_mask=subnet[2], broadcast_address=subnet[3],
         domain_name=subnet[6], domain_name_servers=subnet[5], ntp_servers=subnet[4],
         extra=extra
        )
        
    def reinitialise(self):
        with self._lock:
            self._maps.clear()
            self._subnets.clear()
            self._parse_ini()
        _logger.info("INI-file contents parsed and loaded into memory")
        