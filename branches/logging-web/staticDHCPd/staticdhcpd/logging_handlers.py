import collections
import logging

class FIFOHandler(logging.Handler):
    """
    A handler that always holds a fixed number of records, with FIFO behaviour.
    """
    def __init__(self, capacity):
        logging.Handler.__init__(self)
        self._buffer = collections.deque(capacity)
        
    def emit(self, record):
        self.acquire()
        try:
            self._buffer.appendleft(record)
        finally:
            self.release()
            
    def flush(self):
        self.acquire()
        try:
            self._buffer.clear()
        finally:
            self.release()
            
    def close(self):
        self.flush()
        logging.Handler.close(self)
        
    def readContents(self):
        self.acquire()
        try:
            return tuple(self._buffer)
        finally:
            self.release()
            