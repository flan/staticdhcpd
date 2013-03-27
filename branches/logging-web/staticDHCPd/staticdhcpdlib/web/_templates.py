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
import datetime
import traceback

from .. import config
import _functions

import staticdhcpdlib
import libpydhcpserver

_logger = logging.getLogger('web.server')

from staticdhcpdlib.web import (retrieveDashboardCallbacks, retrieveVisibleMethodCallbacks)

_SYSTEM_NAME = _functions.sanitise(config.SYSTEM_NAME)
_FOOTER = """<div style="float: right;">If you benefit from this system, please <a href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&amp;hosted_button_id=11056045">support it</a></div>
<a href="%(staticdhcpd-url)s">staticDHCPd</a> v%(staticdhcpd-version)s |
<a href="%(libpydhcpserver-url)s">libpydhcpserver</a> v%(libpydhcpserver-version)s""" % {
 'staticdhcpd-url': _functions.sanitise(staticdhcpdlib.URL),
 'staticdhcpd-version': _functions.sanitise(staticdhcpdlib.VERSION),
 'libpydhcpserver-url': _functions.sanitise(libpydhcpserver.URL),
 'libpydhcpserver-version': _functions.sanitise(libpydhcpserver.VERSION),
}
_BOOT_TIME = datetime.datetime.now().replace(microsecond=0)

def _renderHeader():
    current_time = datetime.datetime.now().replace(microsecond=0)
    return """<div style="float: right;">Page generated %(current-time)s</div>
<a href="/" style="color: inherit; font-weight: bold;">%(name)s</a> online for %(uptime)s, since %(boot-time)s""" % {
     'current-time': current_time.ctime(),
     'name': _SYSTEM_NAME,
     'uptime': str(current_time - _BOOT_TIME),
     'boot-time': _BOOT_TIME.ctime(),
    }
    
def _renderFooter():
    return _FOOTER
    
def _renderMain(elements, path, queryargs, mimetype, data, headers):
    output = []
    for element in elements:
        if not element:
            output.append('<hr class="element"/>')
            continue
            
        try:
            result = element.callback(path=path, queryargs=queryargs, mimetype=mimetype, data=data, headers=headers)
            if result is not None:
                output.append('<h1 class="element">%(module)s | %(name)s</h1>' % {
                'module': element.module,
                'name': element.name,
                })
                output.append('<div class="element">')
                output.append(result)
                output.append('</div>')
        except Exception:
            _logger.error("Unable to render dashboard element '%(module)s' '%(name)s':\n%(error)s" % {
             'module': element.module,
             'name': element.name,
             'error': traceback.format_exc(),
            })
    return '\n'.join(output)
    
def _renderMethods():
    output = []
    module = None
    for (element, path) in retrieveVisibleMethodCallbacks():
        if element.module != module:
            if module is not None:
                output.append('</div>')
            module = element.module
            output.append('<h1 class="method">%(module)s</h1>' % {
             'module': element.module,
            })
            output.append('<div class="method">')
        output.append('<a href="%(path)s" style="color: inherit;"%(confirm)s>%(name)s</a><br/>' % {
         'path': path,
         'name': element.name,
         'confirm': element.confirm and ' onclick="return confirm(\'&quot;%(module)s | %(name)s&quot; requested that you confirm your intent to proceed\');"' % {
          'module': element.module,
          'name': element.name,
         } or '',
        })
    else:
        if module is not None:
            output.append('</div>')
    return '\n'.join(output)
    
def _renderTemplate(elements, path, queryargs, mimetype, data, headers, rewrite_location=False):
    return ('application/xhtml+xml; charset=utf-8',
"""<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
    <head>
        <title>%(title)s</title>
        <link rel="stylesheet" type="text/css" href="/css"/>
        <link rel="icon" type="image/x-icon" href="/favicon.ico"/>
        <script type="text/javascript" src="/js"></script>
    </head>
    <body%(rewrite-location)s>
        <div id="content">
            <div id="header">
%(header)s
            </div>
            <div id="methods">
%(methods)s
            </div>
            <div id="main">
%(main)s
            </div>
            <div id="footer">
%(footer)s
            </div>
        </div>
    </body>
</html>
""" % {
     'title': _SYSTEM_NAME,
     'header': _renderHeader(),
     'methods': _renderMethods(),
     'main': _renderMain(elements, path, queryargs, mimetype, data, headers),
     'footer': _renderFooter(),
     'rewrite-location': rewrite_location and ' onload="rewriteLocation(\'/\');"' or '',
    })
    
def renderTemplate(path, queryargs, mimetype, data, headers, element):
    return _renderTemplate((element,), path=path, queryargs=queryargs, mimetype=mimetype, data=data, headers=headers)
    
def renderDashboard(path, queryargs, mimetype, data, headers, featured_element=None):
    elements = retrieveDashboardCallbacks()
    if featured_element:
        elements = [featured_element, None] + list(elements)
        
    return _renderTemplate(elements, path, queryargs, mimetype, data, headers, rewrite_location=bool(featured_element))
    
    
    
    
    
    
    
    
    
    
    

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