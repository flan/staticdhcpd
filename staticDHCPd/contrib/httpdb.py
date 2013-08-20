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

If concurrent connections to your HTTP server should be limited, use
HTTPCachingDatabase and modify the limit it defines.

Like staticDHCPd, this module under the GNU General Public License v3
(C) Neil Tallim, 2013 <flan@uguu.ca>

Created in response to a request from Aleksandr Chusov.
"""
import json
import logging
import urllib2

from staticdhcpdlib.databases.generic import (Definition, Database, CachingDatabase)

_logger = logging.getLogger("contrib.httpdb")

#This class implements your lookup method; to customise this module for your
#site, all you should need to do is edit this section.
class _HTTPLogic(object):
    _URI = 'http://example.org/lookup' #The URI to which data should be sent
    _POST = True #If False, the MAC will be encoded in the query-string as 'mac'
    _HEADERS = {} #Any custom headers your service requires
    
    def _lookupMAC(self, mac):
        """
        Performs the actual lookup operation; this is the first thing you should
        study when customising for your site.
        """
        headers = _HEADERS.copy() #If you need to generate per-request headers, add them here
        
        #You can usually ignore this if-block, though you could strip out whichever method you don't use
        if self._POST:
            headers.update({
             'Content-Type': 'application/json',
            }) #Set the content-type, since there actually is content
            
            request = urllib2.Request(
             self._URI, data=json.dumps({
              'mac': str(mac),
             }, #The request will contain a JSON object like {"mac": "aa:bb:cc:dd:ee:ff"}
             headers=headers,
            )
        else:
            request = urllib2.Request(
             "%(uri)s?mac=%(mac)s" % {
              'uri': self._URI,
              'mac': str(mac).replace(':', '%3A'),
             }, #The request will have a query-string with "mac=aa%3Abb%3Acc%3Add%3Aee%3Aff"
             headers=headers,
            )
            
        _logger.debug("Sending request to '%(uri)s' for '%(mac)s'..." % {
         'uri': self._URI,
         'mac': str(mac),
        })
        try:
            response = urllib.urlopen(request)
            _logger.debug("MAC response received from '%(uri)s' for '%(mac)s'" % {
             'uri': self._URI,
             'mac': str(mac),
            })
            result = json.loads(response.read())
            
            if not result: #The server sent back 'null' or an empty object
                _logger.debug("Unknown MAC response from '%(uri)s' for '%(mac)s'" % {
                 'uri': self._URI,
                 'mac': str(mac),
                })
                return None
                
            #Your server should respond with a JSON object like this:
            #{
            # "ip": "192.168.0.1",
            # "hostname": "any-valid-hostname", //may be omitted or null
            # "gateway": "192.168.0.1", //may be omitted or null
            # "subnet_mask": "255.255.255.0", //may be omitted or null
            # "broadcast_address": "192.168.0.255", //may be omitted or null
            # "domain_name": "example.org", //may be omitted or null
            # "domain_name_servers": "192.168.0.1, 192.168.0.2,192.168.0.3", //may be omitted or null
            # "ntp_servers": "192.168.0.1, 192.168.0.2,192.168.0.3", //may be omitted or null
            # "lease_time": 3600,
            # "subnet": "subnet-id",
            # "serial": 0
            #}
            definition = Definition(
             result['ip'], result.get('hostname'),
             result.get('gateway'), result.get('subnet_mask'), result.get('broadcast_address'),
             result.get('domain_name'), result.get('domain_name_servers'), result.get('ntp_servers'),
             result['lease_time'], result['subnet'], result['serial']
            )
            _logger.debug("Known MAC response from '%(uri)s' for '%(mac)s'" % {
             'uri': self._URI,
             'mac': str(mac),
            })
            return definition
        except Exception, e:
            _logger.error("Failed to lookup '%(mac)s' on '%(uri)s': %(error)s" % {
             'uri': self._URI,
             'mac': str(mac),
             'error': str(e),
            })
            raise
            
            
#Everything below this point is boilerplate code that should not normally need
#to be edited for your site.

class HTTPDatabase(Database, _HTTPLogic):
    def __init__(self):
        _HTTPLogic.__init__(self)
        
    def lookupMAC(self):
        return self._lookupMAC()
        
class HTTPCachingDatabase(CachingDatabase, _HTTPLogic):
    def __init__(self):
        #CachingDatabase.__init__(self, concurrency_limit=20) #The default limit is 2147483647
        CachingDatabase.__init__(self)
        _HTTPLogic.__init__(self)
        