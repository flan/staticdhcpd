# -*- encoding: utf-8 -*-
"""
Provides a basic HTTP(S)-based database for sites that work using RESTful models.

Specifically, this module implements a very generic REST-JSON system, with
optional support for caching. To implement another protocol, only one method
needs to be rewritten, so just look for the comments.

To use this module, make the following changes to conf.py:
    Locate the DATABASE_ENGINE line and replace it with the following two lines:
        import httpdb
        DATABASE_ENGINE = httpdb.HTTPDatabase #or httpdb.HTTPCachingDatabase

    Anywhere above the 'import httpdb' line, define any of the following
    parameters that you need to override:
        #The address of your webservice; MUST BE SET
        X_HTTPDB_URI = 'http://example.org/lookup'
        #Whether 'mac' should be an element in a POSTed JSON object, like
        #{"mac": "aa:bb:cc:dd:ee:ff"}, or encoded in the query-string as 'mac',
        #like "mac=aa%3Abb%3Acc%3Add%3Aee%3Aff"; DEFAULTS TO True
        X_HTTPDB_POST = True
        #Any custom HTTP headers your service requires; DEFAULTS TO {}
        X_HTTPDB_HEADERS = {
            'Your-Company-Token': "hello",
        }
        #If using HTTPCachingDatabase, the maximum number of requests to run
        #at a time; successive requests will block; DEFAULTS TO (effectively)
        #INFINITE
        X_HTTPDB_CONCURRENCY_LIMIT = 10

For a list of all parameters you may define, see below.

If concurrent connections to your HTTP server should be limited, use
HTTPCachingDatabase instead of HTTPDatabase.

Like staticDHCPd, this module under the GNU General Public License v3
(C) Neil Tallim, 2014 <flan@uguu.ca>

Created in response to a request from Aleksandr Chusov.
"""
################################################################################
#Rewrite _parse_server_response() as needed to work with your service.
################################################################################
def _parse_server_response(json_data):
    """
    Transforms a server-response that looks like this...
    {
        "ip": "192.168.0.1",
        "hostname": "any-valid-hostname", //may be omitted or null
        "gateway": "192.168.0.1", //may be omitted or null
        "subnet_mask": "255.255.255.0", //may be omitted or null
        "broadcast_address": "192.168.0.255", //may be omitted or null
        "domain_name": "example.org", //may be omitted or null
        "domain_name_servers": ["192.168.0.1", "192.168.0.2", "192.168.0.3"], //may be omitted or null
        "ntp_servers": ["192.168.0.1", "192.168.0.2", "192.168.0.3"], //may be omitted or null
        "lease_time": 3600,
        "subnet": "subnet-id",
        "serial": 0,
        "extra": {...}, //any extra attributes you would like in the lease-definition; may be omitted or null
    }
    ...into a Definition-object.
    """
    return Definition(
        ip=json_data['ip'], lease_time=json_data['lease_time'],
        subnet=json_data['subnet'], serial=json_data['serial'],
        hostname=json_data.get('hostname'),
        gateways=json_data.get('gateway'),
        subnet_mask=json_data.get('subnet_mask'),
        broadcast_address=json_data.get('broadcast_address'),
        domain_name=json_data.get('domain_name'),
        domain_name_servers=json_data.get('domain_name_servers'),
        ntp_servers=json_data.get('ntp_servers'),
        extra=json_data.get('extra'),
    )

#Do not touch anything below this line
################################################################################
import json
import logging
import urllib2
import netaddr
import traceback

from libpydhcpserver.dhcp_types.mac import MAC
from staticdhcpdlib.databases.generic import (Definition, Database, CachingDatabase)

_logger = logging.getLogger("extension.httpdb")

#This class implements your lookup method; to customise this module for your
#site, all you should need to do is edit this section.
class _HTTPLogic(object):
    def __init__(self):
        from staticdhcpdlib import config

        try:
            self._uri = config.X_HTTPDB_URI
        except AttributeError:
            raise AttributeError("X_HTTPDB_URI must be specified in conf.py")
        self._headers = getattr(config, 'X_HTTPDB_HEADERS', {})
        self._post = getattr(config, 'X_HTTPDB_POST', False)
        self._additional_info = getattr(config, 'X_HTTPDB_ADDITIONAL_INFO', {})
        self._default_name_servers = getattr(config, 'X_HTTPDB_DEFAULT_NAME_SERVERS', '')
        self._default_lease_time = getattr(config, 'X_HTTPDB_DEFAULT_LEASE_TIME', 0)
        self._default_serial = getattr(config, 'X_HTTPDB_DEFAULT_SERIAL', 0)
        self._use_local_relays = getattr(config, 'X_HTTPDB_LOCAL_RELAYS', True)

    def _lookupMAC(self, mac):
        """
        Performs the actual lookup operation; this is the first thing you should
        study when customising for your site.
        """
        global _parse_server_response
        #If you need to generate per-request headers, add them here
        headers = self._headers.copy()

        params = dict(
         {'mac': str(mac)},
         **self._additional_info
        )
        #You can usually ignore this if-block, though you could strip out whichever method you don't use
        if self._post:
            data = json.dumps(params)

            headers.update({
             'Content-Length': str(len(data)),
             'Content-Type': 'application/json',
            })

            request = urllib2.Request(
             self._uri, data=data,
             headers=headers,
            )
        else:
            add_info = '.'.join(['&%s=%s' % (key, value) for key, value in
              self._additional_info.iteritems()])

            request = urllib2.Request(
             "%(uri)s?mac=%(mac)s%(add_info)s" % {
              'uri': self._uri,
              'mac': str(mac).replace(':', '%3A'),
              'add_info': add_info
             },
             headers=headers,
            )

        _logger.debug("Sending request to '%(uri)s' for '%(params)s'" % {
         'uri': self._uri,
         'params': params
        })

        try:
            response = urllib2.urlopen(request)
            _logger.debug("MAC response received from '%(uri)s' for '%(mac)s'" % {
             'uri': self._uri,
             'mac': str(mac),
            })
            results = json.loads(response.read())
            if not isinstance(results, (list,tuple)):
                results = [results]

            if not results: #The server sent back 'null' or an empty object
                _logger.debug("Unknown MAC response from '%(uri)s' for '%(mac)s'" % {
                 'uri': self._uri,
                 'mac': str(mac),
                })
                return None
            _logger.debug("Results from call: %s" % results)

            _logger.debug("Known MAC response from '%(uri)s' for '%(mac)s'" % {
             'uri': self._uri,
             'mac': str(mac),
            })

            return [_parse_server_response(self._set_defaults(result))
              for result in results]
        except Exception, e:
            _logger.error("Failed to lookup '%(mac)s' on '%(uri)s': %(error)s" % {
             'uri': self._uri,
             'mac': str(mac),
             'error': str(e),
            })
            raise

    def _set_defaults(self, json_data):
        """
        Set the default values on a server response if they do not
         already have usable values

        :param dictionary json_data: Dictionary containing response data
        :return dictionary: The modified dictionary with defaults
        """
        if not json_data.get('serial'):
            json_data['serial'] = self._default_serial
        if not json_data.get('domain_name_servers'):
            json_data['domain_name_servers'] = self._default_name_servers
        if not json_data.get('lease_time'):
            json_data['lease_time'] = self._default_lease_time
        return json_data

    def _retrieveDefinition(self, packet_or_mac, packet_type=None, mac=None,
                            ip=None, giaddr=None, pxe_options=None):
        """
        Retrieve the definition matching the input arguments

        :param :class:`libpydhcpserver.dhcp_types.packet.DHCPPacket` or string:
            Either the DHCPPacket representing the request or the MAC
              address to lookup packet being wrapped.
        :param basestring packet_type: The type of packet being processed.
        :param str mac: The MAC of the responding interface, in network-byte
            order.
        :param :class:`libpydhcpserver.dhcp_types.ipv4.IPv4` ip: Value of
            DHCP packet's `requested_ip_address` field.
        :param :class:`libpydhcpserver.dhcp_types.ipv4.IPv4` giaddr: Value of
            the packet's relay IP address
        :param namedtuple pxe_options: PXE options
        :return :class:`databases.generic.Definition` definition: The associated
            definition; None if no "lease" is available.
        """

        if all(x is None for x in [packet_type, mac, ip, giaddr, pxe_options]):
            #packet_or_mac is a MAC address here
            results = self._lookupMAC(packet_or_mac)
            if isinstance(results, (list,tuple)) and len(results) == 1:
                #Only a single result indicates that the IP found
                # isn't ambiguous
                return results[0]

            else:
                #It's ambiguous what result this MAC should be
                # given, so don't return any
                return None

        else:
            #packet_or_mac is a packet
            results = self._lookupMAC(mac)
            if not (isinstance(results, (list, tuple)) or
                    self._use_local_relays):
                return None

            else:
                for result in results:
                    #TODO: Handle RENEW/REBIND where we know the IP address
                    if giaddr and result.subnet_mask:
                        #We can determine the correct result since the
                        # giaddr should exist in the same network as
                        # the response IP address
                        #TODO: What happens under multiple relays in the chain?
                        network = netaddr.IPNetwork(
                         '%s/%s' % (result.ip, result.subnet_mask))

                        if netaddr.IPAddress(str(giaddr)) in network:
                            return result
                else:
                    return None


class HTTPDatabase(Database, _HTTPLogic):
    def __init__(self):
        _HTTPLogic.__init__(self)

    def lookupMAC(self, packet_or_mac, packet_type=None, mac=None, ip=None,
                  giaddr=None, pxe_options=None):
        return self._retrieveDefinition(packet_or_mac, packet_type, mac, ip,
                                        giaddr, pxe_options)

class HTTPCachingDatabase(CachingDatabase, _HTTPLogic):
    def __init__(self):
        from staticdhcpdlib import config
        if hasattr(config, 'X_HTTPDB_CONCURRENCY_LIMIT'):
            CachingDatabase.__init__(self, concurrency_limit=config.X_HTTPDB_CONCURRENCY_LIMIT)
        else:
            CachingDatabase.__init__(self)
        _HTTPLogic.__init__(self)

    def lookupMAC(self, packet_or_mac, packet_type=None, mac=None, ip=None,
                  giaddr=None, pxe_options=None):
        cache_mac = packet_or_mac if type(packet_or_mac) == MAC else mac

        if self._cache and cache_mac:
            try:
                definition = self._cache.lookupMAC(cache_mac)
            except Exception as exc:
                _logger.error("Cache lookup failed:\n%s" % exc, exc_info=True)
            else:
                if definition:
                    return definition
        definition = self._retrieveDefinition(packet_or_mac, packet_type, mac, ip,
                                              giaddr, pxe_options)
        if definition and self._cache and cache_mac:
            try:
                self._cache.cacheMAC(cache_mac, definition)
            except Exception as exc:
                _logger.error("Cache update failed:\n%s" % exc, exc_info=True)
        return definition

http_database = None
def _handle_unknown_mac(packet, packet_type, mac, ip,
                        giaddr, pxe_options):
    """
    Handles case where MAC was not found in initial lookup

    :param :class:`libpydhcpserver.dhcp_types.packet.DHCPPacket` packet: The
        packet being wrapped.
    :param basestring packet_type: The type of packet being processed.
    :param str mac: The MAC of the responding interface, in network-byte order.
    :param :class:`libpydhcpserver.dhcp_types.ipv4.IPv4` ip: Value of
        DHCP packet's `requested_ip_address` field.
    :param :class:`libpydhcpserver.dhcp_types.ipv4.IPv4` giaddr: Value of
        the packet's relay IP address
    :param namedtuple pxe_options: PXE options
    :return :class:`databases.generic.Definition` definition: The associated
         definition; None if no "lease" is available.
    """
    if not http_database:
        #We need to ensure that the init happens after the config
        # is fully loaded, but don't want it to create a new instance
        # every time; So do it on the first call
        global http_database
        http_database = HTTPDatabase()

    _logger.debug('Unknown MAC %(mac)s (ip=%(ip)s; giaddr=%(giaddr)s)' % {'mac':mac, 'ip':ip, 'giaddr':giaddr})
    return http_database.lookupMAC(packet, packet_type, mac, ip,
                                   giaddr, pxe_options)
