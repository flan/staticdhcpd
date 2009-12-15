import threading
import time

try:
	import netifaces
except ImportError:
	try:
		import dependencies.netifaces.osx_106_26.netifaces as netifaces
	except ImportError:
		sys.stderr.write("Unable to load netifaces module")
		exit(1)
		
SYSTEM_NAME = 'staticDHCPd'
LOG_CAPACITY = 1000

SERVER_IP = None
SERVER_PORT = 67
CLIENT_PORT = 68

_LOG_LOCK = threading.Lock()
_LOG = []

def init():
	iface = 'en0'
	try:
		global SERVER_IP
		SERVER_IP = netifaces.ifaddresses(iface)[2][0]['addr']
	except Exception, e:
		sys.stderr.write('Unable to determine address of interface %(iface)s\n' % {
		 'iface': iface,
		})
		exit(1)
		
	writeLog('Configuration loaded')
	
def writeLog(data):
	_LOG_LOCK.acquire()
	try:
		_LOG.insert(0, (time.time(), data))
		_LOG = _LOG[:1000]
	finally:
		_LOG_LOCK.release()
		
def readLog():
	_LOG_LOCK.acquire()
	try:
		return tuple(_LOG)
	finally:
		_LOG_LOCK.release()
		