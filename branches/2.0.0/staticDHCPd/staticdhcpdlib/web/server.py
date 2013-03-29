# -*- encoding: utf-8 -*-
"""
staticDHCPd module: web.server

Purpose
=======
 Provides a web interface for browsers and service-consumers.
 
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
import BaseHTTPServer
import cgi
import hashlib
import logging
import re
import SocketServer
import threading
import time
import traceback
import uuid

try:
    from urlparse import parse_qs
except:
    from cgi import parse_qs

from staticdhcpdlib.web import retrieveMethodCallback

from .. import config
import _templates
from . import (WEB_METHOD_DASHBOARD, WEB_METHOD_TEMPLATE, WEB_METHOD_RAW)

_logger = logging.getLogger('web.server')

_AUTHORIZATION_RE = re.compile(r'^(?P<key>.+?)="?(?P<value>.+?)"?$')
_NONCE_TIMEOUT = 120.0 #: The number of seconds to wait for the client to try again.
_OPAQUE = uuid.uuid4().hex
_NONCES = []
_NONCE_LOCK = threading.Lock()
def _flush_expired_nonces():
    current_time = time.time()
    stale_nonces = []
    with _NONCE_LOCK:
        for (i, (nonce, timeout)) in enumerate(_NONCES):
            if current_time >= timeout:
                stale_nonces.append(i)
                _logger.debug("Nonce %(nonce)s expired" % {
                 'nonce': nonce,
                })
        for i in reversed(stale_nonces):
            del _NONCES[i]
            
def _generateNonce():
    nonce = uuid.uuid4().hex
    timeout = time.time() + _NONCE_TIMEOUT
    with _NONCE_LOCK:
        _NONCES.append((nonce, timeout))
    return nonce
    
def _locateNonce(nonce, remove=False):
    with _NONCE_LOCK:
        for (i, (n, _)) in enumerate(_NONCES):
            if nonce == n:
                if remove:
                    del _NONCES[i]
                    _logger.debug("Nonce %(nonce)s deleted" % {
                     'nonce': nonce,
                    })
                return True
        return False
        
def _parseAuthorization(authorization):
    parameters = (p.strip() for p in authorization[authorization.find(' ') + 1:].split(','))
    result = {}
    for parameter in parameters:
        if parameter:
            match = _AUTHORIZATION_RE.match(parameter)
            if match:
                result[match.group('key').lower()] = match.group('value')
    return result
    
def _validateCredentials(parameters, method):
    try:
        _logger.debug("DIGEST via %(method)s; details: %(details)r" % {
         'method': method,
         'details': parameters,
        })
        
        nonce = parameters['nonce'].lower()
        cnonce = parameters['cnonce'].lower()
        
        ha1 = hashlib.md5("%(username)s:%(realm)s:%(password)s" % {
         'username': config.WEB_DIGEST_USERNAME,
         'realm': config.SYSTEM_NAME.replace('"', "'"),
         'password': config.WEB_DIGEST_PASSWORD,
        }).hexdigest()
        
        ha2 = hashlib.md5("%(method)s:%(uri)s" % {
         'method': method,
         'uri': parameters['uri']
        }).hexdigest()
        
        if parameters.get('qop', '').lower() == 'auth':
            target = hashlib.md5("%(ha1)s:%(nonce)s:%(count)s:%(cnonce)s:%(qop)s:%(ha2)s" % {
             'ha1': ha1,
             'nonce': nonce,
             'count': parameters['nc'].lower(),
             'cnonce': cnonce,
             'qop': parameters['qop'].lower(),
             'ha2': ha2,
            }).hexdigest()
        else:
            target = hashlib.md5("%(ha1)s:%(nonce)s:%(ha2)s" % {
             'ha1': ha1,
             'nonce': nonce,
             'ha2': ha2,
            }).hexdigest()
            
        return target == parameters['response'].lower()
    except Exception, e:
        raise ValueError("Authorisation data from client is not spec-compliant: " + str(e))
        
def _isSecure(headers, method):
    _flush_expired_nonces()
    
    authorization = headers.getheader('authorization')
    if not authorization:
        _logger.debug("No authentication credentials supplied")
        raise _RequestAuthorizationRequired(_generateNonce(), False)
        
    parameters = _parseAuthorization(authorization)
    if not parameters.get('opaque') == _OPAQUE:
        _logger.debug("Invalid opaque value supplied")
        raise _RequestAuthorizationRequired(_generateNonce(), False)
        
    if not _locateNonce(parameters.get('nonce')):
        _logger.debug("Stale nonce supplied")
        raise _RequestAuthorizationRequired(_generateNonce(), True)
        
    if _validateCredentials(parameters, method):
        _logger.debug("Authentication succeeded")
        _locateNonce(parameters.get('nonce'), remove=True)
    else:
        _logger.debug("Invalid authentication credentials supplied")
        raise _RequestAuthorizationRequired(_generateNonce(), False)
        
def _validateRequest(headers, method, secure):
    if secure and (config.WEB_DIGEST_USERNAME and config.WEB_DIGEST_PASSWORD):
        _isSecure(headers, method)
        
def _webMethod(method_type):
    """
    A decorator to deal with web-flows.
    
    @type method_type: basestring
    @param method_type: The type of method requested.
    """
    def decorator(http_method):
        def wrappedHandler(self):
            start_time = time.time()
            _logger.debug("Received %(method)s from %(host)s:%(port)i for %(path)s" % {
             'method': method_type,
             'host': self.client_address[0],
             'port': self.client_address[1],
             'path': self.path,
            })
            try:
                (path, queryargs) = (self.path.split('?', 1) + [''])[:2]
                queryargs = parse_qs(queryargs)
                
                cacheable = False
                handler = None
                #First, see if it matches a registered callback
                callback = retrieveMethodCallback(path)
                if callback:
                    _validateRequest(self.headers, method_type, callback.secure or (callback.display_mode == WEB_METHOD_DASHBOARD and config.WEB_DASHBOARD_SECURE))
                    cacheable = callback.cacheable
                    if callback.display_mode == WEB_METHOD_DASHBOARD:
                        handler = lambda path, queryargs, mimetype, data, headers : _templates.renderDashboard(path, queryargs, mimetype, data, headers, featured_element=callback)
                    elif callback.display_mode == WEB_METHOD_TEMPLATE:
                        handler = lambda path, queryargs, mimetype, data, headers : _templates.renderTemplate(path, queryargs, mimetype, data, headers, callback)
                    else:
                        handler = callback.callback
                elif path == '/':
                    _validateRequest(self.headers, method_type, config.WEB_DASHBOARD_SECURE)
                    handler = _templates.renderDashboard
                else:
                    raise _NotFound(path)
                    
                (mimetype, data) = http_method(self)
                (mimetype, data) = handler(path, queryargs, mimetype, data, self.headers)
                self.send_response(200)
                self.send_header('Last-Modified', time.strftime('%a, %d %b %Y %H:%M:%S %Z'))
                self.send_header('Content-Type', mimetype)
                self.send_header('Content-Length', len(data))
                if not cacheable:
                    self.send_header('Expires', 'Tue, 03 Jul 2001 06:00:00 GMT')
                    self.send_header('Cache-Control', 'max-age=0, no-cache, must-revalidate, proxy-revalidate')
                self.end_headers()
                self.wfile.write(data)
            except _NotFound, e:
                _logger.debug("Request made for unbound path: %(path)s" % {
                 'path': str(e),
                })
            except _RequestAuthorizationRequired, e:
                _logger.debug("Authentication required to access %(path)s: %(nonce)s" % {
                 'path': self.path,
                 'nonce': e.nonce,
                })
                self.send_response(401)
                auth = [
                 ('realm', config.SYSTEM_NAME.replace('"', "'")),
                 ('qop', 'auth'),
                 ('algorithm', 'MD5'),
                 ('nonce', e.nonce),
                 ('opaque', _OPAQUE),
                ]
                if e.stale:
                    auth.append(('stale', 'TRUE'))
                self.send_header(
                 'WWW-Authenticate',
                 'Digest ' + ', '.join('%(key)s="%(value)s"' % {'key': key, 'value': value,} for (key, value) in auth)
                )
                self.end_headers()
            except Exception:
                error = traceback.format_exc()
                _logger.error("Problem while processing request for '%(path)s' via %(method)s:\n%(error)s" % {
                 'path': self.path,
                 'method': method_type,
                 'error': error,
                })
                self.send_response(500)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Content-Length', len(error))
                self.end_headers()
                self.wfile.write(error)
            finally:
                _logger.debug("Processed %(method)s from %(host)s:%(port)i for %(path)s in %(time).4f seconds" % {
                 'method': method_type,
                 'host': self.client_address[0],
                 'port': self.client_address[1],
                 'path': self.path,
                 'time': time.time() - start_time,
                })
        return wrappedHandler
    return decorator
    
class _WebHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    @_webMethod('GET')
    def do_GET(self):
        return (None, None)
        
    @_webMethod('POST')
    def do_POST(self):
        (content_type, _) = cgi.parse_header(self.headers.getheader('content-type'))
        content_length = int(self.headers.getheader('content-length'))
        return (content_type, self.rfile.read(content_length))
        
    def log_message(*args):
        """
        Just a stub to suppress automatic webserver log messages.
        """
        
class WebService(threading.Thread):
    """
    A thread that handles HTTP requests indefinitely, daemonically.
    """
    _web_server = None #: The handler that responds to HTTP requests.
    
    def __init__(self):
        """
        Sets up the Web server.
        
        @raise Exception: If a problem occurs while binding the sockets needed
            to handle HTTP traffic.
        """
        threading.Thread.__init__(self)
        self.name = "Webservice"
        self.daemon = True
        
        _logger.info("Prepared to bind to %(address)s:%(port)i" % {
         'address': config.WEB_IP,
         'port': config.WEB_PORT,
        })
        class _ThreadedServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer): pass
        self._web_server = _ThreadedServer((config.WEB_IP, config.WEB_PORT), _WebHandler)
        _logger.info("Configured Webservice engine")
        
    def run(self):
        """
        Runs the Web server indefinitely.
        
        In the event of an unexpected error, e-mail will be sent and processing
        will continue with the next request.
        """
        _logger.info('Webservice engine beginning normal operation')
        while True:
            try:
                self._web_server.handle_request()
            except Exception:
                _logger.critical("Unhandled exception:\n" + traceback.format_exc())
                
class _RequestAuthorizationRequired(Exception):
    def __init__(self, nonce, stale):
        self.nonce = nonce
        self.stale = stale
        
class _NotFound(Exception): pass
