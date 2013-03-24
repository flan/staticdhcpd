# -*- encoding: utf-8 -*-
"""
staticDHCPd module: web.methods

Purpose
=======
 Provides implementations of several helpful web-components.
 
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
import cgi
import logging

from .. import config
from .. import logging_handlers
import resources

_logger = logging.getLogger('web.methods')

class Logger(object):
    _logger = None
    
    def __init__(self):
        _logger.info("Configuring web-accessible logging...")
        self._logger = logging_handlers.FIFOHandler(config.WEB_LOG_HISTORY)
        self._logger.setLevel(getattr(logging, config.WEB_LOG_SEVERITY))
        if config.DEBUG:
            self._logger.setFormatter(logging.Formatter("%(asctime)s : %(levelname)s : %(message)s"))
        else:
            self._logger.setFormatter(logging.Formatter("%(asctime)s : %(message)s"))
        _logger.root.addHandler(self._logger)
        _logger.info("Web-accessible logging online; buffer-size=" + str(config.WEB_LOG_HISTORY))
        
    def render(self, path, queryargs, mimetype, data, headers):
        return '<br/>\n'.join((cgi.escape(line) for line in self._logger.readContents()))
        
def css(path, queryargs, mimetype, data, headers):
    return ('text/css', resources.CSS)
    
def favicon(path, queryargs, mimetype, data, headers):
    return ('image/vnd.microsoft.icon', resources.FAVICON)
    