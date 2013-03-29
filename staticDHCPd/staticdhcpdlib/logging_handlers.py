# -*- encoding: utf-8 -*-
"""
staticDHCPd module: logging_handlers

Purpose
=======
 Provides application-specific implementations of logging-friendly handlers.
 
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

class FIFOHandler(logging.Handler):
    """
    A handler that holds a fixed number of records, with FIFO behaviour.
    """
    def __init__(self, capacity):
        logging.Handler.__init__(self)
        self._records = collections.deque(maxlen=capacity)
        
    def emit(self, record):
        self.acquire()
        try:
            self._records.appendleft(record)
        finally:
            self.release()
            
    def flush(self):
        self.acquire()
        try:
            self._records.clear()
        finally:
            self.release()
            
    def close(self):
        self.flush()
        logging.Handler.close(self)
        
    def readContents(self):
        self.acquire()
        try:
            return [(record.levelno, self.format(record)) for record in self._records]
        finally:
            self.release()
            