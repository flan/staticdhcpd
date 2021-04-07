# -*- encoding: utf-8 -*-
"""
staticdhcpdlib.web.headers
==========================
Provides implementations of the default <head/> elements.

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

(C) Neil Tallim, 2021 <neil.tallim@linux.com>
"""
import logging

from .. import config
from . import functions

_logger = logging.getLogger('web.headers')

def contentType(*args, **kwargs):
    """
    Provides the default content-type HTML header.
    
    :return str: The content-type header.
    """
    return '<meta http-equiv="content-type" content="application/xhtml+xml; charset=utf-8"/>'
    
_TITLE = '<title>' + functions.sanitise(config.SYSTEM_NAME) + '</title>' #: The title of the web interface
def title(*args, **kwargs):
    """
    Provides the default title HTML header.
    
    :return str: The title header.
    """
    return _TITLE
    
def css(*args, **kwargs):
    """
    Provides the default CSS HTML header.
    
    :return str: The CSS header.
    """
    return '<link rel="stylesheet" type="text/css" href="/css"/>'
    
def favicon(*args, **kwargs):
    """
    Provides the default favicon HTML header.
    
    :return str: The favicon header.
    """
    return '<link rel="icon" type="image/x-icon" href="/favicon.ico"/>'
    
def javascript(*args, **kwargs):
    """
    Provides the default JavaScript HTML header.
    
    :return str: The JavaScript header.
    """
    return '<script type="text/javascript" src="/javascript"></script>'
    
