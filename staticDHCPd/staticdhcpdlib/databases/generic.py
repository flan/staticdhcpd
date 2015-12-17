# -*- encoding: utf-8 -*-
"""
staticdhcpdlib.databases.generic
================================
Provides a uniform datasource API, to be implemented by technology-specific
backends.

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
(C) Anthony Woods, 2013 <awoods@internap.com>
"""
try:
    from types import StringTypes
except ImportError: #py3k
    StringTypes = (str,)
try:
    IntTypes = (int, long,)
except NameError: #py3k
    IntTypes = (int,)

import collections
import logging
import threading
import traceback

import libpydhcpserver.dhcp_types.conversion
from libpydhcpserver.dhcp_types.ipv4 import IPv4

_logger = logging.getLogger('databases.generic')

class Definition(object):
    """
    A definition of a "lease" from a database.
    """
    ip = None #: The :class:`IPv4 <IPv4>` to be assigned
    hostname = None #: The hostname to assign (may be None)
    gateways = None #: The :class:`IPv4 <IPv4>` gateways to advertise (may be None)
    subnet_mask = None #: The :class:`IPv4 <IPv4>` netmask to advertise (may be None)
    broadcast_address = None #: The :class:`IPv4 <IPv4>` broadcast address to advertise (may be None)
    domain_name = None #: The domain name to advertise (may be None)
    domain_name_servers = None #: A list of DNS IPv4s to advertise (may be None)
    ntp_servers = None #: A list of NTP IPv4s to advertise (may be None)
    lease_time = None #: The number of seconds for which the lease is valid
    subnet = None #: The "subnet" identifier of the record in the database
    serial = None #: The "serial" identifier of the record in the database
    extra = None #: An object containing any metadata from the database

    def __init__(self,
        ip, lease_time, subnet, serial,
        hostname=None,
        gateways=None, subnet_mask=None, broadcast_address=None,
        domain_name=None, domain_name_servers=None, ntp_servers=None,
        extra=None
    ):
        """
        Initialises a Definition.

        :param ip: The IP address to assign, in any main format.
        :param int lease_time: The number of seconds for which the lease is
                               valid.
        :param basestring subnet: The "subnet" identifier of the record in the
                                  database.
        :param int serial: The "serial" identifier of the record in the
                           database.
        :param basestring hostname: The hostname to assign.
        :param gateways: The IP addresses to advertise, in any main format,
                         including comma-delimited string.
        :param subnet_mask: The IP address to advertise, in any main format.
        :param broadcast_address: The IP address to advertise, in any main
                                  format.
        :param basestring domain_name: The domain name to advertise.
        :param domain_name_servers: The IP addresses to advertise, in any main
                                    format, including comma-delimited string.
        :param ntp_servers: The IP addresses to advertise, in any main format,
                            including comma-delimited string.
        :param extra: An object containing any metadata from the
                                 database.
        """
        #Required values
        self.ip = self._parse_address(ip)
        if not self.ip:
            raise ValueError("An IP address is required for assignment; received: %(ip)r" % {'ip': ip,})
        self.lease_time = int(lease_time)
        self.subnet = str(subnet)
        self.serial = int(serial)

        #Optional vlaues
        self.hostname = hostname and str(hostname)
        self.gateways = self._parse_addresses(gateways)
        self.subnet_mask = self._parse_address(subnet_mask)
        self.broadcast_address = self._parse_address(broadcast_address)
        self.domain_name = domain_name and str(domain_name)
        self.domain_name_servers = self._parse_addresses(domain_name_servers, limit=3)
        self.ntp_servers = self._parse_addresses(ntp_servers, limit=3)
        self.extra = extra

    def _parse_address(self, address):
        """
        Takes an input-value and produces an IPv4 address.

        :param address: The IP address to process, in any main format.
        :return: The parsed IPv4 address, or ``None`` if nothing was
                 provided.
        """
        if isinstance(address, IPv4):
            return address
        if address:
            return IPv4(address)
        return None

    def _parse_addresses(self, addresses, limit=None):
        """
        Takes variable-type input and produces IPv4 addresses.

        :param addresses: The IP addresses to process, in any main format,
                          including comma-delimited string.
        :param int limit: The maximum number of addresses to return.
        :return list: Any parsed IPv4 addresses, or ``None`` if nothing was
                      provided.
        """
        if isinstance(addresses, IPv4):
            return [addresses]
        if addresses:
            if isinstance(addresses, StringTypes):
                addresses = addresses.split(',')
            elif isinstance(addresses, collections.Sequence):
                if all(type(i) in IntTypes for i in addresses):
                    return conversion.listToIPs(addresses)[:limit]
            else: #Might be a set or something non-sliceable
                addresses = tuple(addresses)
            return [self._parse_address(i) for i in addresses[:limit]] or None
        return None

class Database(object):
    """
    A stub describing the features a Database object must provide.
    """
    def lookupMAC(self, mac):
        """
        Queries the database for the given MAC address and returns the IP and
        associated details if the MAC is known.

        :param mac: The MAC address to lookup.
        :return: The :class:`Definition` or, if no match was found, ``None``.
        :raise Exception: A problem occured while accessing the database.
        """
        raise NotImplementedError("lookupMAC() must be implemented by subclasses")

    def reinitialise(self):
        """
        Though subclass-dependent, this will generally result in some guarantee
        that the database will provide fresh data, whether that means flushing
        a cache or reconnecting to the source.
        """

class CachingDatabase(Database):
    """
    A partial implementation of the Database engine, adding efficient generic
    caching logic and concurrency-throttling.
    """
    _resource_lock = None #: A lock used to prevent the database from being overwhelmed.
    _cache = None #: The caching structure to use, if caching is desired.

    def __init__(self, concurrency_limit=2147483647):
        """
        A fully implemented caching layer for any real database.

        :param int concurrency_limit: The number of concurrent database hits to
                                      permit, defaulting to a ridiculously large
                                      number.
        :raise Exception: Cache-initialisation failed.
        """
        _logger.debug("Initialising database with a maximum of %(count)i concurrent connections" % {'count': concurrency_limit,})
        self._resource_lock = threading.BoundedSemaphore(concurrency_limit)
        try:
            self._setupCache()
        except Exception, e:
            _logger.error("Cache initialisation failed:\n" + traceback.format_exc())

    def _setupCache(self):
        """
        Sets up the database caching environment.

        :except Exception: Cache-initialisation failed.
        """
        from .. import config
        if config.USE_CACHE:
            import _caching
            if config.PERSISTENT_CACHE or config.CACHE_ON_DISK:
                try:
                    disk_cache = _caching.DiskCache(config.PERSISTENT_CACHE and 'persistent' or 'disk', config.PERSISTENT_CACHE)
                    if config.CACHE_ON_DISK:
                        _logger.debug("Combining local caching database and persistent caching database")
                        self._cache = disk_cache
                    else:
                        _logger.debug("Setting up memory-cache on top of persistent caching database")
                        self._cache = _caching.MemoryCache('memory', chained_cache=disk_cache)
                except Exception, e:
                    _logger.error("Unable to initialise disk-based caching:\n" + traceback.format_exc())
                    if config.PERSISTENT_CACHE and not config.CACHE_ON_DISK:
                        _logger.warn("Persistent caching is not available")
                        self._cache = _caching.MemoryCache('memory-nonpersist')
                    elif config.CACHE_ON_DISK:
                        _logger.warn("Caching is disabled: memory-caching was not requested, so no fallback exists")
            elif config.MEMCACHED_CACHE:
                _logger.debug("Setting up memcached-cache")
                self._cache = _caching.MemcachedCache('memcached', (config.MEMCACHED_SERVER,
                                                      config.MEMCACHED_PORT), config.MEMCACHED_AGE_TIME)
            else:
                _logger.debug("Setting up memory-cache")
                self._cache = _caching.MemoryCache('memory')

            if self._cache:
                _logger.info("Database caching enabled; top-level cache: " + str(self._cache))
            else:
                _logger.warn("Database caching could not be enabled")
        else:
            if config.PERSISTENT_CACHE:
                _logger.warn("PERSISTENT_CACHE was set, but USE_CACHE was not")
            if config.CACHE_ON_DISK:
                _logger.warn("CACHE_ON_DISK was set, but USE_CACHE was not")

    def reinitialise(self):
        if self._cache:
            try:
                self._cache.reinitialise()
            except Exception, e:
                _logger.error("Cache reinitialisation failed:\n" + traceback.format_exc())

    def lookupMAC(self, mac):
        if self._cache:
            try:
                definition = self._cache.lookupMAC(mac)
            except Exception, e:
                _logger.error("Cache lookup failed:\n" + traceback.format_exc())
            else:
                if definition:
                    return definition

        with self._resource_lock:
            definition = self._lookupMAC(mac)
        if definition and self._cache:
            try:
                self._cache.cacheMAC(mac, definition)
            except Exception, e:
                _logger.error("Cache update failed:\n" + traceback.format_exc())
        return definition

class Null(Database):
    """
    A database that never serves anything, useful primarily for testing or if
    custom modules are loaded that work in the handleUnknownMAC() workflow.
    """
    def lookupMAC(self, mac):
        return None
