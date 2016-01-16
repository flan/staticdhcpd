# -*- encoding: utf-8 -*-
"""
Provides a basic HTTP(S)-based database for sites that work using RESTful models.

Specifically, this module implements a very generic REST-JSON system, with
optional support for caching. To implement another protocol, only one method
needs to be rewritten, so just look for the comments.

To use this module without making any code changes, make the following changes
to conf.py; if anything more sophisticated is required, fork it and hack away:
    Locate the DATABASE_ENGINE line and replace it with the following two lines:
        import httpdb
        DATABASE_ENGINE = httpdb.HTTPDatabase #or httpdb.HTTPCachingDatabase

    Anywhere above the 'import httpdb' line, define any of the following
    parameters that you need to override:
        #The address of your webservice; MUST BE SET
        X_HTTPDB_URI = 'http://example.org/lookup'
        #Additional parameters to be passed with the request, DEFAULTS TO {}
        X_HTTPDB_PARAMETERS = {
            'some_request_thing': 7002,
        }
        #The parameter-key for the MAC; defaults to 'mac'
        X_HTTPDB_PARAMETER_KEY_MAC = 'hwaddr'
        #Whether the parameters should be serialised to JSON and POSTed, like
        #{"mac": "aa:bb:cc:dd:ee:ff"}, or encoded in the query-string, like
        #"mac=aa%3Abb%3Acc%3Add%3Aee%3Aff"; DEFAULTS TO True
        X_HTTPDB_POST = True
        #Any custom HTTP headers your service requires; DEFAULTS TO {}
        X_HTTPDB_HEADERS = {
            'Your-Site-Token': "hello",
        }
        #If using HTTPCachingDatabase, the maximum number of requests to run
        #at a time; successive requests will block; DEFAULTS TO (effectively)
        #INFINITE
        X_HTTPDB_CONCURRENCY_LIMIT = 10
        
For a list of all parameters you may define, see below.

If concurrent connections to your HTTP server should be limited, use
HTTPCachingDatabase instead of HTTPDatabase.

Like staticDHCPd, this module under the GNU General Public License v3
(C) Neil Tallim, 2016 <flan@uguu.ca>

Created in response to a request from Aleksandr Chusov.
Enhanced with feedback from Helios de Creisquer.
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
import urllib
import urllib2

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
        self._parameters = getattr(config, 'X_HTTPDB_PARAMETERS', {})
        self._parameter_key_mac = getattr(config, 'X_HTTPDB_PARAMETER_KEY_MAC', 'mac')
        self._post = getattr(config, 'X_HTTPDB_POST', True)
        
    def _lookupMAC(self, mac):
        """
        Performs the actual lookup operation; this is the first thing you should
        study when customising for your site.
        """
        global _parse_server_response
        
        #If you need to generate per-request headers, add them here
        headers = self._headers.copy()
        
        #To alter the parameters supplied with the request, alter this
        parameters = self._parameters.copy()
        #Dynamic items 
        parameters.update({
            self._parameter_key_mac: str(mac),
        })
        
        #You can usually ignore this if-block, though you could strip out whichever method you don't use
        if self._post:
            data = json.dumps(parameters)
            
            headers.update({
                'Content-Length': str(len(data)),
                'Content-Type': 'application/json',
            })
            
            request = urllib2.Request(
                self._uri, data=data,
                headers=headers,
            )
        else:
            request = urllib2.Request(
             "%(uri)s?%(parameters)s" % {
                'uri': self._uri,
                'parameters': urllib.urlencode(parameters, doseq=True),
             },
             headers=headers,
            )
            
        _logger.debug("Sending request to '%(uri)s' for '%(mac)s'..." % {
            'uri': self._uri,
            'mac': str(mac),
        })
        try:
            response = urllib2.urlopen(request)
            _logger.debug("MAC response received from '%(uri)s' for '%(mac)s'" % {
                'uri': self._uri,
                'mac': str(mac),
            })
            result = json.loads(response.read())
            
            if not result: #The server sent back 'null' or an empty object
                _logger.debug("Unknown MAC response from '%(uri)s' for '%(mac)s'" % {
                    'uri': self._uri,
                    'mac': str(mac),
                })
                return None
                
            definition = _parse_server_response(result)
            
            _logger.debug("Known MAC response from '%(uri)s' for '%(mac)s'" % {
                'uri': self._uri,
                'mac': str(mac),
            })
            return definition
        except Exception, e:
            _logger.error("Failed to lookup '%(mac)s' on '%(uri)s': %(error)s" % {
                'uri': self._uri,
                'mac': str(mac),
                'error': str(e),
            })
            raise
            
class HTTPDatabase(Database, _HTTPLogic):
    def __init__(self):
        _HTTPLogic.__init__(self)
        
    def lookupMAC(self, mac):
        return self._lookupMAC(mac)
        
class HTTPCachingDatabase(CachingDatabase, _HTTPLogic):
    def __init__(self):
        if hasattr(config, 'X_HTTPDB_CONCURRENCY_LIMIT'):
            CachingDatabase.__init__(self, concurrency_limit=config.X_HTTPDB_CONCURRENCY_LIMIT)
        else:
            CachingDatabase.__init__(self)
        _HTTPLogic.__init__(self)
        