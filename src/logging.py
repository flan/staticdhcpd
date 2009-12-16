import threading
import time

import conf

_LOG_LOCK = threading.Lock()
_LOG = []

_POLL_RECORDS_LOCK = threading.Lock()
_POLL_RECORDS = []

def writeLog(data):
	global _LOG
	
	_LOG_LOCK.acquire()
	try:
		_LOG = [(time.time(), data)] + _LOG[:conf.LOG_CAPACITY - 1]
	finally:
		_LOG_LOCK.release()
		
def readLog():
	_LOG_LOCK.acquire()
	try:
		return tuple(_LOG)
	finally:
		_LOG_LOCK.release()
		
def writePollRecord(packets, discarded, time_taken, ignored_macs):
	global _POLL_RECORDS
	
	_POLL_RECORDS_LOCK.acquire()
	try:
		_POLL_RECORDS = [(time.time(), packets, discarded, time_taken, ignored_macs)] + _POLL_RECORDS[:conf.POLL_INTERVALS_TO_TRACK - 1]
	finally:
		_POLL_RECORDS_LOCK.release()
		
def readPollRecords():
	_POLL_RECORDS_LOCK.acquire()
	try:
		return tuple(_POLL_RECORDS)
	finally:
		_POLL_RECORDS_LOCK.release()
		