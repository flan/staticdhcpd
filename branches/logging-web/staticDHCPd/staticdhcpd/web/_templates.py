# -*- encoding: utf-8 -*-
"""
staticDHCPd module: web._templated

Purpose
=======
 Handles all core templating requirements for rendering things like the
 dashboard.
 
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
import logging
import traceback

from staticdhcpd import VERSION as _staticdhcpd_VERSION
from libpydhcpserver import VERSION as _libpydhcpserver_VERSION

_logger = logging.getLogger('web.server')

from staticdhcpd.web import (retrieveDashboardCallbacks, retrieveVisibleMethodCallbacks)

#A web package should be created, to contain things like CSS (and images?), which can be served
#via registered methods

#To sort methods, use the following logic:
#module = None
#for (element, path) in sorted((element, path) for (path, element) in _web_methods.items() if not element.hidden):
#    if element.module != module:
#        <create a new section>
#    <add entry>

def _renderTemplate(elements):
    output = []
    
    module = None
    for (element, path) in retrieveVisibleMethodCallbacks():
        if element.module != module:
            output.append(element.module)
        output.append(element.name)
        output.append(element.confirm)
        output.append(path)
        
    for element in elements:
        try:
            output.append(element())
        except Exception:
            _logger.error("Unable to render dashboard element '%(module)s'/'%(name)s':\n%(error)s" % {
             'module': element.module,
             'name': element.name,
             'error': traceback.format_exc(),
            })
            output.append("An error occurred while processing this element; see logs for details")
            
    return ('application/xhtml+xml', ''.join(output))
    
def renderTemplate(path, queryargs, mimetype, data, headers, element):
    return _renderTemplate((lambda : element(mimetype, data),))
    
def renderDashboard(path, queryargs, mimetype, data, headers, featured_element=None):
    elements = []
    callbacks = retrieveDashboardCallbacks()
    for c in callbacks:
        elements.append(lambda : c(path, queryargs, mimetype, data, headers))
        
    if featured_element:
        elements.append(lambda : element(mimetype, data))
        
    return _renderTemplate(elements)
    
    
    
    
    
    
    
    
    
    
    

"""
        Renders the current state of the memory-log as HTML for consumption by
        the client.
        try:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.send_header('Last-modified', time.strftime('%a, %d %b %Y %H:%M:%S %Z'))
            self.end_headers()
            
            self.wfile.write('<html><head><title>%(name)s log</title></head><body>' % {'name': config.SYSTEM_NAME,})
            self.wfile.write('<div style="width: 950px; margin-left: auto; margin-right: auto; border: 1px solid black;">')
            
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
"""