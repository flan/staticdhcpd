import threading
import time

import conf

_LOG_LOCK = threading.Lock()
_LOG = []

def writeLog(data):
	global _LOG
	
	_LOG_LOCK.acquire()
	try:
		_LOG.insert(0, (time.time(), data))
		_LOG = _LOG[:conf.LOG_CAPACITY]
	finally:
		_LOG_LOCK.release()
		
def readLog():
	_LOG_LOCK.acquire()
	try:
		return tuple(_LOG)
	finally:
		_LOG_LOCK.release()
		