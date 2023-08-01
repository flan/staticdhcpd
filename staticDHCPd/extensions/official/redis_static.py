# -*- encoding: utf-8 -*-
"""
Provides a means of using a Redis server to implement static addressing in a
manner that may be shared by multiple StaticDHCPd instances.

The redis-py package is required.
This module does not support Sentinel or Cluster operation. Please feel free to
modify it to meet your own needs if this is something you require.

To use this module without making any code changes, make the following changes
to conf.py; if anything more sophisticated is required, fork it and hack away:
    Locate the DATABASE_ENGINE line and replace it with the following two lines:
        import staticDHCPd_extensions.redis_static as redis_static
        DATABASE_ENGINE = redis_static.RedisDatabase #or redis_static.RedisCachingDatabase

    Anywhere above the 'import redis_static' line, specify any Redis connection parameters
    that you need to override, such as the following (see redis-py for a full list):
        X_REDISDB_KWARGS = {
            'host': '1.2.3.4',
            'port': 1234,
            'db': 0,
        }
        #If using RedisCachingDatabase, the maximum number of requests to run
        #at a time; successive requests will block; DEFAULTS TO (effectively)
        #INFINITE
        X_REDISDB_CONCURRENCY_LIMIT = 10
        
    Your database is expected to allow for MAC addresses to be used as keys for hashes,
    like '11:aa:22:bb:33:cc', within which assigned values will be keyed:
    {
        "ip": "192.168.0.1",
        "subnet": "subnet-id",
        "serial": 0,
        "lease_time": 3600, //may be omitted
        "hostname": "any-valid-hostname", //may be omitted
        "subnet_mask": "255.255.255.0", //may be omitted
        "gateway": "192.168.0.1", //may be omitted
        "broadcast_address": "192.168.0.255", //may be omitted
        "domain_name": "example.org", //may be omitted
        "domain_name_servers": "192.168.0.1,192.168.0.2, 192.168.0.3", //may be omitted; limit: 3 entries
        "ntp_servers": "192.168.0.1,192.168.0.2, 192.168.0.3", //may be omitted; limit: 3 entries
        "extra": <json-string>, //any extra attributes you would like in the lease-definition; may be omitted
    }
    
    Every (subnet, serial) pair associated with a MAC must be defined under another key,
    identified as '<subnet>|<serial>' like '10.0.0.0/24|0', within which default values
    will be keyed:
    {
        "lease_time": 3600, //value in seconds
        "subnet_mask": "255.255.255.0", //may be omitted
        "gateway": "192.168.0.1", //may be omitted
        "broadcast_address": "192.168.0.255", //may be omitted
        "domain_name": "example.org", //may be omitted
        "domain_name_servers": "192.168.0.1,192.168.0.2, 192.168.0.3", //may be omitted; limit: 3 entries
        "ntp_servers": "192.168.0.1,192.168.0.2, 192.168.0.3", //may be omitted; limit: 3 entries
        "extra": <json-string>, //any extra attributes you would like in the lease-definition; may be omitted
    }

If concurrent connections to your Redis server should be limited, use
RedisCachingDatabase instead of RedisDatabase.

Like staticDHCPd, this module under the GNU General Public License v3
(C) Neil Tallim, 2023 <neil.tallim@linux.com>
"""

import json
import logging
import uuid

import redis

from staticdhcpdlib.databases.generic import (Definition, Database, CachingDatabase)

_logger = logging.getLogger("extension.redisdb")

class _RedisLogic(object):
    _redis_client = None #a connection-pool behind the scenes
    
    def __init__(self):
        from staticdhcpdlib import config
        
        self._redis_client = redis.Redis(
            decode_responses=True,
            **getattr(config, 'X_REDISDB_KWARGS', {}),
        )
        
    def _lookupMAC(self, mac):
        details = self._redis_client.hgetall(str(mac))
        if not details:
            _logger.debug("Unknown MAC response for '{}'".format(mac))
            return None
        _logger.debug("Known MAC response for '{}': {!r}".format(mac, details))
        
        subnet_serial = '{}|{}'.format(details['subnet'], details['serial'])
        details_ss = self._redis_client.hgetall(subnet_serial)
        if not details_ss:
            _logger.warning("Unknown subnet|serial: '{}'".format(subnet_serial))
            return None
        _logger.debug("Known subnet|serial response for '{}': {!r}".format(subnet_serial, details_ss))
        
        #prepare response
        
        extra = details_ss.get('extra')
        combined_extra = extra and json.loads(extra) or {}
        extra = details.get('extra')
        combined_extra.update(extra and json.loads(extra) or {})
        if not combined_extra:
            combined_extra = None
            
        domain_name_servers = details.get('domain_name_servers', details_ss.get('domain_name_servers'))
        if domain_name_servers:
            domain_name_servers = [v.strip() for v in domain_name_servers.split(',')][:3]
            
        ntp_servers = details.get('ntp_servers', details_ss.get('ntp_servers'))
        if ntp_servers:
            ntp_servers = [v.strip() for v in ntp_servers.split(',')][:3]
            
        return Definition(
            ip=details['ip'], lease_time=details.get('lease_time', details_ss['lease_time']),
            subnet=details['subnet'], serial=details['serial'],
            hostname=details.get('hostname'),
            gateways=details.get('gateway', details_ss.get('gateway')),
            subnet_mask=details.get('subnet_mask', details_ss.get('subnet_mask')),
            broadcast_address=details.get('broadcast_address', details_ss.get('broadcast_address')),
            domain_name=details.get('domain_name', details_ss.get('domain_name')),
            domain_name_servers=domain_name_servers,
            ntp_servers=ntp_servers,
            extra=combined_extra,
        )
        
class RedisDatabase(Database, _RedisLogic):
    def __init__(self):
        _RedisLogic.__init__(self)

    def lookupMAC(self, mac):
        return self._lookupMAC(mac)

class RedisCachingDatabase(CachingDatabase, _RedisLogic):
    def __init__(self):
        from staticdhcpdlib import config
        
        if hasattr(config, 'X_REDISDB_CONCURRENCY_LIMIT'):
            CachingDatabase.__init__(self, concurrency_limit=config.X_REDISDB_CONCURRENCY_LIMIT)
        else:
            CachingDatabase.__init__(self)
            
        _RedisLogic.__init__(self)
