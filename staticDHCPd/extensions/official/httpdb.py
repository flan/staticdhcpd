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
        
        #If X_HTTPDB_POST is False, you can provide the URI format with
        X_HTTPDB_FORMAT = '%(uri)s?mac=%(mac)s' #(default)

        #If X_HTTPDB_USER is defined, look for X_HTTPDB_PASS and use it
        #with basic authentication (Default to None)
        X_HTTPDB_USER = myuser
        X_HTTPDB_PASS = mypass

        #Any custom HTTP headers your service requires;
        #DEFAULTS TO {'Accept': 'application/json',}

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
from base64 import encodestring
# Python2&3 compatible imports
try:
    from urllib.request import urlopen, Request
    from urllib.parse import urlencode
except ImportError:
    from urllib  import urlencode
    from urllib2 import urlopen, Request


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
        self._headers = getattr(config, 'X_HTTPDB_HEADERS', {'Accept': 'application/json',})
        self._format = getattr(config, 'X_HTTPDB_FORMAT', "%(uri)s?%(querystring)s")
        self._post = getattr(config, 'X_HTTPDB_POST', True)
        self._user = getattr(config, 'X_HTTPDB_USER', None)
        self._pass = getattr(config, 'X_HTTPDB_PASS', None)

    def _lookupATTRS(self, attrs):
        """
        Performs the actual lookup operation; this is the first thing you should
        study when customising for your site.
        """
        global _parse_server_response
        
        #If you need to generate per-request headers, add them here
        headers = self._headers.copy()
        _logger.debug("HTTPDB Attributes: '%(attrs)s'..." % {
            'attrs': str(attrs),
            })

        ## Handle basic authentication...
        if self._user and self._pass:
            b64auth = encodestring(('%s:%s' % (self._user, self._pass)).encode())
            headers.update({
             'Authorization': 'Basic %s' % b64auth.decode().strip('\n')
            })
        
        #You can usually ignore this if-block, though you could strip out whichever method you don't use
        if self._post:
            data = json.dumps(attrs)
            
            headers.update({
             'Content-Length': str(len(data)),
             'Content-Type': 'application/json',
            })
            
            request = Request(
             self._uri, data=data,
             headers=headers,
            )
            _logger.debug("Sending POST request to '%(uri)s' with JSON data from '%(attrs)s'..." % {
                'uri': request.get_full_url(),
                'attrs': str(attrs),
                })
        else:
            request = Request(
             self._format % {
              'uri': self._uri,
              'querystring': urlencode(attrs),
              'mac': str(attrs['mac']),
             },
             headers=headers,
            )
            _logger.debug("Sending GET request to '%(uri)s' with Querystring from '%(attrs)s'..." % {
                'uri': request.get_full_url(),
                'attrs': str(attrs),
                })
            
        try:
            response = urlopen(request)
            _logger.debug("OK response received from '%(uri)s' for '%(attrs)s'" % {
             'uri': self._uri,
             'attrs': str(attrs),
            })
            result = json.loads(response.read())
            
            if not result: #The server sent back 'null' or an empty object
                _logger.debug("NOTOK response from '%(uri)s' for '%(attrs)s'" % {
                 'uri': self._uri,
                 'attrs': str(attrs),
                })
                return None
                
            definition = _parse_server_response(result)
            
            _logger.debug("PARSE_OK response from '%(uri)s' for '%(attrs)s'" % {
             'uri': self._uri,
             'attrs': str(attrs),
            })
            return definition
        except Exception, e:
            _logger.error("PARSE_FAIL for response from '%(uri)s' for '%(attrs)s: %(error)s" % {
             'uri': self._uri,
             'attrs': str(attrs),
             'error': str(e),
            })
            raise

class HTTPDatabase(Database, _HTTPLogic):
    def __init__(self):
        _HTTPLogic.__init__(self)
        
    def lookupMAC(self, mac):
        return self._lookupATTRS({'mac': str(mac),})

    def lookupATTRS(self, attrs):
        return self._lookupATTRS(attrs)
        
class HTTPCachingDatabase(CachingDatabase, _HTTPLogic):
    def __init__(self):
        if hasattr(config, 'X_HTTPDB_CONCURRENCY_LIMIT'):
            CachingDatabase.__init__(self, concurrency_limit=config.X_HTTPDB_CONCURRENCY_LIMIT)
        else:
            CachingDatabase.__init__(self)
        _HTTPLogic.__init__(self)
        
