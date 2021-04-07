# -*- encoding: utf-8 -*-
"""
staticdhcpdlib.logging_handlers
===============================
Provides application-specific implementations of logging-friendly handlers.
 
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
import collections
import logging

class FIFOHandler(logging.Handler):
    """
    A handler that holds a fixed number of records, with FIFO behaviour.
    """
    def __init__(self, capacity):
        """
        Initialises the handler in a blank state.
        
        :param int capacity: The number of records the handler can hold.
        """
        logging.Handler.__init__(self)
        self._records = collections.deque(maxlen=capacity)
        
    def emit(self, record):
        """
        Called by the logging subsystem whenever new data is received.
        
        :param record: A logging record.
        """
        self.acquire()
        try:
            self._records.appendleft(record)
        finally:
            self.release()
            
    def flush(self):
        """
        Discards all logged records.
        """
        self.acquire()
        try:
            self._records.clear()
        finally:
            self.release()
            
    def close(self):
        """
        Called by the logging subsystem whenever the handler is closed.
        """
        self.flush()
        logging.Handler.close(self)
        
    def readContents(self):
        """
        Produces the current log.
        
        :return list(str): The logged records, in human-readable form.
        """
        self.acquire()
        try:
            return [(record.levelno, self.format(record)) for record in self._records]
        finally:
            self.release()
            
