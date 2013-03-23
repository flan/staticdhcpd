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
import os
import SocketServer
import threading
import time
import traceback

try:
    from urlparse import parse_qs
except:
    from cgi import parse_qs

import config


from staticdhcpd import VERSION as _staticdhcpd_VERSION
from libpydhcpserver import VERSION as _libpydhcpserver_VERSION

_logger = logging.getLogger('web.server')
_web_logger = None





#A web package should be created, to contain things like CSS (and images?), which can be served
#via registered methods


#To sort methods, use the following logic:
#module = None
#for (element, path) in sorted((element, path) for (path, element) in _web_methods.items() if not element.hidden):
#    if element.module != module:
#        <create a new section>
#    <add entry>


class _WebHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """
    The handler that responds to all received HTTP requests.
    """
    _allowed_pages = ('/', '/index.html',) #: A collection of all paths that will be allowed.
    
    def do_GET(self):
        """
        Handles all HTTP GET requests.
        """
        if not self.path in self._allowed_pages:
            self.send_response(404)
            return
        self._doResponse()
        
    def do_HEAD(self):
        """
        Handles all HTTP HEAD requests.
        
        This involves lying about the existence of files and telling the browser
        to always pull a fresh copy.
        """
        if not self.path in self._allowed_pages:
                self.send_response(404)
                return
                
        try:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.send_header('Last-modified', time.strftime('%a, %d %b %Y %H:%M:%S %Z'))
            self.end_headers()
        except Exception:
            _logger.error("Problem while processing HEAD:\n" + traceback.format_exc())
            
    def do_POST(self):
        """
        Handles all HTTP POST requests.
        
        This checks to see if the user entered the flush key and, if so,
        flushes the cache and writes the memory-log to disk.
        """
        try:
            """(ctype, pdict) = cgi.parse_header(self.headers.getheader('content-type'))
            if ctype == 'application/x-www-form-urlencoded':
                query = parse_qs(self.rfile.read(int(self.headers.getheader('content-length'))))
                key = query.get('key')
                if key:
                    if hashlib.md5(key[0]).hexdigest() == config.WEB_RELOAD_KEY:
                        system.reinitialise()
                        
                        if logging.logToDisk():
                            logging.writeLog("Wrote log to '%(log)s'" % {'log': config.LOG_FILE,})
                        else:
                            logging.writeLog("Unable to write log to '%(log)s'" % {'log': config.LOG_FILE,})
                    else:
                        logging.writeLog("Invalid Web-access-key provided")
            """
            _logger.warn("POST not yet reimplemented")
        except Exception:
            _logger.error("Problem while processing POST:\n" + traceback.format_exc())
        self._doResponse()
        
    def _doResponse(self):
        """
        Renders the current state of the memory-log as HTML for consumption by
        the client.
        """
        try:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.send_header('Last-modified', time.strftime('%a, %d %b %Y %H:%M:%S %Z'))
            self.end_headers()
            
            self.wfile.write('<html><head><title>%(name)s log</title></head><body>' % {'name': config.SYSTEM_NAME,})
            self.wfile.write('<div style="width: 950px; margin-left: auto; margin-right: auto; border: 1px solid black;">')
            
            """
            self.wfile.write('<div>Statistics:<div style="text-size: 0.9em; margin-left: 20px;">')
            for (timestamp, packets, discarded, time_taken, ignored_macs) in logging.readPollRecords():
                if packets:
                    turnaround = time_taken / packets
                else:
                    turnaround = 0.0
                self.wfile.write("%(time)s : received: %(received)i; discarded: %(discarded)i; turnaround: %(turnaround)fs/pkt; ignored MACs: %(ignored)i<br/>" % {
                 'time': time.ctime(timestamp),
                 'received': packets,
                 'discarded': discarded,
                 'turnaround': turnaround,
                 'ignored': ignored_macs,
                })
            self.wfile.write("</div></div><br/>")
            """
            
            self.wfile.write('<div>Events:<div style="text-size: 0.9em; margin-left: 20px;">')
            for line in _web_logger.readContent():
                self.wfile.write("%(line)s<br/>" % {
                 'line': cgi.escape(line),
                })
            self.wfile.write("</div></div><br/>")
            
            self.wfile.write('<div style="text-align: center;">')
            self.wfile.write('<small>Summary generated %(time)s</small><br/>' % {
             'time': time.asctime(),
            })
            self.wfile.write('<small>%(server)s:%(port)i | PID: %(pid)i | v%(core_version)s | <a href="http://uguu.ca/" onclick="window.open(this.href); return false;">uguu.ca</a></small><br/>' % {
             'pid': os.getpid(),
             'server': config.DHCP_SERVER_IP,
             'port': config.DHCP_SERVER_PORT,
             'core_version': VERSION,
            })
            self.wfile.write('<form action="/" method="post"><div style="display: inline;">')
            self.wfile.write('<label for="key">Key: </label><input type="password" name="key" id="key"/>')
            if config.USE_CACHE:
                self.wfile.write('<input type="submit" value="Flush cache and write log to disk"/>')
            else:
                self.wfile.write('<input type="submit" value="Write log to disk"/>')
            self.wfile.write('</div></form>')
            self.wfile.write('</div>')
            
            self.wfile.write("</div></body></html>")
        except Exception:
            _logger.error("Problem while serving Response:\n" + traceback.format_exc())
            
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
                
