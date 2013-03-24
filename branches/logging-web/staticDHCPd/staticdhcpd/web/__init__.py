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
    Allows for modular registration of dashboard callbacks, to be invoked
    in the order of registration.
    
    If the given callback is already present, it will not be registered a second
    time.
    
    @type module: basestring
    @param module: The human-friendly name of the module to which the element
        belongs.
    @type name: basestring
    @param name: The human-friendly name of the element, within the module.
    @type callback: callbale
    @param callback: The callable to be invoked when the dashboard is rendered;
        must accept the parameters 'path', 'queryargs', 'mimetype', 'data', and
        'headers'; must be tolerant of any parameters being None; must return
        data as a string, formatted as XHTML, to be embedded inside of a <div/>,
        or None to suppress inclusion.
    @type ordering: number|None
    @param ordering: A bias-specifier that controls where this element will
        appear in relation to others. If omitted, the value will be that of the
        highest number plus one. Negatives are valid.
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
            element = _WebDashboardElement(ordering, module, name, callback)
            _web_dashboard.append(element)
            _web_dashboard.sort()
            _logger.debug("Registered %(element)r" % {'element': element,})
            
def unregisterDashboardCallback(callback):
    """
    Allows for modular unregistration of dashboard callbacks.
    
    If the given callback is not present, this is a no-op.
    
    @type callback: callbale
    @param callback: The callable to be invoked when the dashboard is rendered;
        must not require any parameters; must return data formatted as XHTML, to
        be embedded inside of a <div/>.
    """
    with _web_lock:
        for (i, element) in enumerate(_web_dashboard):
            if element.callback is callback:
                del _web_dashboard[i]
                break
            else:
                _logger.error("Dashboard callback %(callback)r is not registered" % {'callback': callback,})
                
def retrieveDashboardCallbacks():
    """
    Returns all registered callbacks.
    
    @rtype: tuple of L{_WebDashboardElement}s
    @return: All registered callbacks.
    """
    with _web_lock:
        return tuple(_web_dashboard)
        
def registerMethodCallback(path, module, name, hidden, secure, confirm, div_content, show_in_dashboard, callback):
    """
    Allows for modular registration of method callbacks.
    
    @type path: str
    @param path: The path at which to register this callback, typically
        something like "ca/uguu/puukusoft/statcDHCPd/statistics/histogram.csv",
        but as long as it's a valid URI-fragment, it's up to you.
        If the given path is already present, it will not be overwritten.
    @type module: basestring
    @param module: The human-friendly name of the module to which the method
        belongs.
    @type name: basestring
    @param name: The human-friendly name of the method, within the module.
    @type hidden: bool
    @param hidden: Whether the method should be rendered on the interface.
    @type secure: bool
    @param secure: Whether DIGEST authentication will be required to access the
        method.
    @type confirm: bool
    @param confirm: Whether JavaScript validation will be used to prompt the
        user to confirm that they want to perform the chosen action.
    @type div_content: bool
    @param div_content: Whether the returned data will be XHTML-formatted
        content, to be placed inside of a dashboard-like <div/>.
    @type show_in_dashboard: bool
    @param show_in_dashboard: Whether the method's contents, if div_content,
        should be shown alongside dashboard elements. (Good for confirmation
        messages)
    @type callback: callbale
    @param callback: The callable to be invoked when the method is called; must
        accept the parameters 'path', 'queryargs', 'mimetype', 'data', and
        'headers'; must be tolerant of any parameters being None; must return a
        tuple of (mimetype, data, headers), with data being a (binary) string.
    """
    with _web_lock:
        if path in _web_methods:
            _logger.error("'%(path)s' is already registered" % {'path': path,})
        else:
            _web_methods[path] = _WebMethod(module, name, hidden, secure, confirm, div_content, show_in_dashboard, callback)
            _logger.debug("Registered %(path)s" % {'path': path,})
            
def unregisterMethodCallback(path):
    """
    Allows for modular unregistration of method callbacks.
    
    @type path: str
    @param path: The path at which the callback was registered.
        If the given path is not present, this is a no-op.
    """
    with _web_lock:
        try:
            del _web_methods[path]
        except KeyError:
            _logger.error("'%(path)s' is not registered" % {'path': path,})
            
def retrieveMethodCallback(path):
    """
    Returns a registered callback, if one exists.
    
    @type path: basestring
    @param path: The path at which the callback was registered.
    
    @rtype: L{_WebMethod}|None
    @return: The registered method, if nay.
    """
    with _web_lock:
        return _web_methods.get(path)
        
def retrieveVisibleMethodCallbacks():
    """
    Returns all visible method callbacks, in lexically sorted order.
    
    @rtype: tuple of (L{_WebMethod}, path:basestring)
    @return: All visible method callbacks.
    """
    with _web_lock:
        return tuple(sorted((element, path) for (path, element) in _web_methods.items() if not element.hidden))
        