# -*- encoding: utf-8 -*-
"""
staticdhcpdlib.web
==================
Defines web-registration methods and structures.
 
Legal
-----
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

(C) Neil Tallim, 2014 <flan@uguu.ca>
"""
import collections
import logging
import threading

import functions

_logger = logging.getLogger('web')

_web_lock = threading.Lock()
_web_headers = []
_web_dashboard = []
_web_methods = {}

_WebDashboardElement = collections.namedtuple("WebDashboardElement", ('ordering', 'module', 'name', 'callback'))
"""
A component of the dashboard.

.. py:attribute:: ordering

    An integer used to sort this element against others

.. py:attribute:: module

    The name of the module to which this element belongs

.. py:attribute:: name

    The name under which to display the element

.. py:attribute:: callback

    The method to invoke when rendering this element
"""
_WebMethod = collections.namedtuple("WebMethod", (
 'module', 'name', 'hidden', 'secure', 'confirm', 'display_mode', 'cacheable', 'callback'
))
"""
An invokable method.

.. py:attribute:: module

    The name of the module to which this method belongs

.. py:attribute:: name

    The name under which to display the method

.. py:attribute:: hidden

    Whether the method should be advertised on the dashboard

.. py:attribute:: secure

    Whether the method requires authorization

.. py:attribute:: confirm

    Whether the method, when invoked from the dashboard, requires confirmation

.. py:attribute:: display_mode

    Whether the method's callback presents information to display as part of
    the dashboard, on its own, or as raw bytes

.. py:attribute:: cacheable

    Whether the method's response can be cached

.. py:attribute:: callback

    The method to invoke when rendering this element
"""

#Method-rendering constants
WEB_METHOD_DASHBOARD = 1 #: The content is rendered before the dashboard
WEB_METHOD_TEMPLATE = 2 #: The content is rendered in the same container that would normally show the dashboard, but no dashboard elements are present
WEB_METHOD_RAW = 3 #: The content is presented exactly as returned, identified by the given MIME-type

def registerHeaderCallback(callback):
    """
    Installs an element in the headers; at most one instance of any given
    ``callback`` will be accepted.
    
    :param callable callback: Must accept the parameters `path`, `queryargs`,
                              `mimetype`, `data`, and `headers`, with the
                              possibility that `mimetype` and `data` may be
                              None; `queryargs` is a dictionary of parsed
                              query-string items, with values expressed as lists
                              of strings; `headers` is a dictionary-like object.
                              
                              It must return data as a string, formatted as
                              XHTML, to be embedded inside of <head/>, or None
                              to suppress inclusion.
    """
    with _web_lock:
        if callback in _web_headers:
            _logger.error("%(callback)r is already registered" % {'callback': callback,})
        else:
            _web_headers.append(callback)
            _logger.debug("Registered header %(callback)r" % {'callback': callback,})
            
def unregisterHeaderCallback(callback):
    """
    Removes a header element.
    
    :param callable callback: The element to be removed.
    :return bool: True if an element was removed.
    """
    with _web_lock:
        try:
            _web_headers.remove(callback)
        except ValueError:
            _logger.error("header %(callback)r is not registered" % {'callback': callback,})
            return False
        else:
            _logger.error("header %(callback)r unregistered" % {'callback': callback,})
            return True
            
def retrieveHeaderCallbacks():
    """
    Enumerates header callback elements.
    
    :return tuple: All header callbacks, in registration order.
    """
    with _web_lock:
        return tuple(_web_headers)
        
def registerDashboardCallback(module, name, callback, ordering=None):
    """
    Installs an element in the dashboard; at most one instance of any given
    ``callback`` will be accepted.
    
    :param basestring module: The name of the module to which this element
                              belongs.
    :param basestring name: The name under which to display the element.
    :param callable callback: Must accept the parameters `path`, `queryargs`,
                              `mimetype`, `data`, and `headers`, with the
                              possibility that `mimetype` and `data` may be
                              None; `queryargs` is a dictionary of parsed
                              query-string items, with values expressed as lists
                              of strings; `headers` is a dictionary-like object.
                              
                              It must return data as a string, formatted as
                              XHTML, to be embedded inside of a <div/>, or None
                              to suppress inclusion.
    :param int ordering: A number that controls where this element will appear
                         in relation to others. If not specified, the value will
                         be that of the highest number plus one, placing it at
                         the end; negatives are valid.
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
            element = _WebDashboardElement(ordering, functions.sanitise(module), functions.sanitise(name), callback)
            _web_dashboard.append(element)
            _web_dashboard.sort()
            _logger.debug("Registered dashboard element %(element)r" % {'element': element,})
            
def unregisterDashboardCallback(callback):
    """
    Removes a dashboard element.
    
    :param callable callback: The element to be removed.
    :return bool: True if an element was removed.
    """
    with _web_lock:
        for (i, element) in enumerate(_web_dashboard):
            if element.callback is callback:
                del _web_dashboard[i]
                _logger.debug("Unregistered dashboard element %(element)r" % {'element': element,})
                return True
        else:
            _logger.error("Dashboard callback %(callback)r is not registered" % {'callback': callback,})
            return False
            
def retrieveDashboardCallbacks():
    """
    Enumerates dashboard callback elements.
    
    :return tuple: All dashboard callbacks, in display order.
    """
    with _web_lock:
        return tuple(_web_dashboard)
        
def registerMethodCallback(path, callback, cacheable=False, hidden=True, secure=False, module=None, name=None, confirm=False, display_mode=WEB_METHOD_RAW):
    """
    Installs a webservice method; at most one instance of ``path`` will be
    accepted.
    
    :param basestring path: The location at which the service may be called,
        like "/ca/uguu/puukusoft/staticDHCPd/extension/stats/histograph.csv".
    :param callable callback: Must accept the parameters `path`, `queryargs`,
                              `mimetype`, `data`, and `headers`, with the
                              possibility that `mimetype` and `data` may be
                              None; `queryargs` is a dictionary of parsed
                              query-string items, with values expressed as lists
                              of strings; `headers` is a dictionary-like object.
                              
                              It must return a tuple of (mimetype, data,
                              headers), with data being a string or bytes-like
                              object.
    :param bool cacheable: Whether the client is allowed to cache the method's
                           content.
    :param bool hidden: Whether to render a link in the side-bar.
    :param bool secure: Whether authentication will be required before this
                        method can be called.
    :param basestring module: The name of the module to which this element
                              belongs.
    :param basestring name: The name under which to display the element.
    :param bool confirm: Adds JavaScript validation to ask the user if they're
                         sure they know what they're doing before the method
                         will be invoked, if not `hidden`.
    :param display_mode: One of the WEB_METHOD_* constants.
    """
    with _web_lock:
        if path in _web_methods:
            _logger.error("'%(path)s' is already registered" % {'path': path,})
        else:
            _web_methods[path] = method = _WebMethod(
             functions.sanitise(module), functions.sanitise(name),
             hidden, secure, confirm, display_mode, cacheable, callback
            )
            _logger.debug("Registered method %(method)r at %(path)s" % {'method': method, 'path': path,})
            
def unregisterMethodCallback(path):
    """
    Removes a method element.
    
    :param basestring path: The element to be removed.
    :return bool: True if an element was removed.
    """
    with _web_lock:
        try:
            del _web_methods[path]
        except KeyError:
            _logger.error("'%(path)s' is not registered" % {'path': path,})
            return False
        else:
            _logger.debug("Unregistered method %(path)s" % {'path': path,})
            return True
            
def retrieveMethodCallback(path):
    """
    Retrieves a method callback element.
    
    :return callable: The requested method, or None if unbound.
    """
    with _web_lock:
        return _web_methods.get(path)
        
def retrieveVisibleMethodCallbacks():
    """
    Enumerates method callback elements.
    
    :return tuple: All method callbacks, as (`element`, `path`) tuples, in
                  lexically sorted order.
    """
    with _web_lock:
        return tuple(sorted((element, path) for (path, element) in _web_methods.items() if not element.hidden))
        