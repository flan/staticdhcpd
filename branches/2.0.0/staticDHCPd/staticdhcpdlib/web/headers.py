# -*- encoding: utf-8 -*-
"""
staticDHCPd module: web.headers

Purpose
=======
 Provides implementations of the default <head/> elements.
 
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

from .. import config
import _functions

_logger = logging.getLogger('web.headers')

def contentType(*args, **kwargs):
    return '<meta http-equiv="content-type" content="application/xhtml+xml; charset=utf-8"/>'
    
_TITLE = '<title>' + _functions.sanitise(config.SYSTEM_NAME) + '</title>'
def title(*args, **kwargs):
    return _TITLE
    
def css(*args, **kwargs):
    return '<link rel="stylesheet" type="text/css" href="/css"/>'
    
def favicon(*args, **kwargs):
    return '<link rel="icon" type="image/x-icon" href="/favicon.ico"/>'
    
def javascript(*args, **kwargs):
    return '<script type="text/javascript" src="/javascript"></script>'
    