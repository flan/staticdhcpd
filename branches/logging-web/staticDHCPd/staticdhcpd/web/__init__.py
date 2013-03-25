# -*- encoding: utf-8 -*-
"""
staticDHCPd package: web

Purpose
=======
 Defines web-registration methods and structures.
 
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
import collections
import logging
import threading

import _functions

_logger = logging.getLogger('web')

_web_lock = threading.Lock()
_web_dashboard = []
_web_methods = {}

_WebDashboardElement = collections.namedtuple("WebDashboardElement", ('ordering', 'module', 'name', 'callback'))
_WebMethod = collections.namedtuple("WebMethod", (
 'module', 'name', 'hidden', 'secure', 'confirm', 'div_content', 'show_in_dashboard', 'callback'
))

def registerDashboardCallback(module, name, callback, ordering=None):
    """
    Installs an element in the dashboard; at most one instance of any given
    `callback` will be accepted.
    
    `module` and `name` describe how it will be presented, both as
    human-readable strings.
    
    The `callback` must accept the parameters 'path', 'queryargs', 'mimetype',
    'data', and 'headers', with the possibility that 'mimetype' and 'data' may
    be None; 'queryargs' is a dictionary of parsed query-string items, with
    values expressed as lists of strings; 'headers' is a
    `Python BasicHTTPServer` headers object.
    
    It must return data as a string, formatted as XHTML, to be embedded inside
    of a <div/>, or None to suppress inclusion.
    
    To control where the element will appear, supply `ordering`. This is a
    number that controls where this element will appear in relation to
    others. If omitted, the value will be that of the highest number plus one,
    placing it at the end; negatives are valid.
    """
    with _web_lock:
        for (i, element) in enumerate(_web_dashboard):
            if element.callback is callback:
                _logger.error("%(element)r is already registered" % {'element': element,})
                break
        else:
            if ordering is None:
                if _web_dashboard:
                    ordering = _web_dashboard[-1].ordering + 1
                else:
                    ordering = 0
            element = _WebDashboardElement(ordering, _functions.sanitise(module), _functions.sanitise(name), callback)
            _web_dashboard.append(element)
            _web_dashboard.sort()
            _logger.debug("Registered dashboard element %(element)r" % {'element': element,})
            
def unregisterDashboardCallback(callback):
    """
    Removes the specified element, identified by `callback, from the dashboard.
    """
    with _web_lock:
        for (i, element) in enumerate(_web_dashboard):
            if element.callback is callback:
                del _web_dashboard[i]
                _logger.debug("Unregistered dashboard element %(element)r" % {'element': element,})
                break
            else:
                _logger.error("Dashboard callback %(callback)r is not registered" % {'callback': callback,})
                
def retrieveDashboardCallbacks():
    """
    Returns every registered callback, in display-order.
    """
    with _web_lock:
        return tuple(_web_dashboard)
        
def registerMethodCallback(path, module, name, hidden, secure, confirm, div_content, show_in_dashboard, callback):
    """
    Installs a webservice method; at most one instance of `path` will be
    accepted.
    
    `path` is the location at which the service may be called, like
    "ca/uguu/puukusoft/statcDHCPd/statistics/histogram.csv".
    
    `module` and `name` describe how it will be presented, both as
    human-readable strings. Only if `hidden` is False, though.
    
    `secure` controls whether DIGEST authentication will be required before this
    method can be called.
    
    `confirm` adds JavaScript validation to ask the user if they're sure they
    know what they're doing before the method will be invoked, if not `hidden`.
    
    `div_content`, if True, will place the data inside of the same sort of
    template used by the dashboard, and `show_in_dashboard` will take it a step
    further, rendering the returned content before the rest of the dashboard,
    which is good for confirmation-like actions.
    
    
    The `callback` must accept the parameters 'path', 'queryargs', 'mimetype',
    'data', and 'headers', with the possibility that 'mimetype' and 'data' may
    be None; 'queryargs' is a dictionary of parsed query-string items, with
    values expressed as lists of strings; 'headers' is a
    `Python BasicHTTPServer` headers object.
    
    It must return a tuple of (mimetype, data, headers), with data being a
    string or bytes-like object.
    """
    with _web_lock:
        if path in _web_methods:
            _logger.error("'%(path)s' is already registered" % {'path': path,})
        else:
            _web_methods[path] = _WebMethod(
             _functions.sanitise(module), _functions.sanitise(name),
             hidden, secure, confirm, div_content, show_in_dashboard, callback
            )
            _logger.debug("Registered method %(path)s" % {'path': path,})
            
def unregisterMethodCallback(path):
    """
    Removes the method registered at `path`.
    """
    with _web_lock:
        try:
            del _web_methods[path]
            _logger.debug("Unregistered method %(path)s" % {'path': path,})
        except KeyError:
            _logger.error("'%(path)s' is not registered" % {'path': path,})
            
def retrieveMethodCallback(path):
    """
    Returns the `_WebMethod` registered at `path`, if one exists.
    """
    with _web_lock:
        return _web_methods.get(path)
        
def retrieveVisibleMethodCallbacks():
    """
    Returns all visible (`_WebMethod`, `path`)s, in lexically sorted order.
    """
    with _web_lock:
        return tuple(sorted((element, path) for (path, element) in _web_methods.items() if not element.hidden))
        