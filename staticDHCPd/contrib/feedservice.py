# -*- encoding: utf-8 -*-
"""
Integrates an Atom feed into the webservice module, allowing you to subscribe to
events of importance, without all the noise that often accompanies e-mail
updates, especially when something fails on every single request, like someone
pulling a cable they shouldn't have touched.

To use this module, customise the constants below, then add the following to
conf.py's init() function:
    import feedservice
    
Like staticDHCPd, this module under the GNU General Public License v3
(C) Neil Tallim, 2013 <flan@uguu.ca>
"""
import staticdhcpdlib.config as config
################################################################################
#Do not touch anything above this line

#The address at which your server can be reached
#Defaults to the given web-address, if not '0.0.0.0'; 'localhost' otherwise
#Rewrite it as needed
_server_ip = (config.WEB_IP != '0.0.0.0' and config.WEB_IP or 'localhost')
SERVER_BASE = 'http://' + _server_ip + ':' + str(config.WEB_PORT)

#The minimum severity of events to include
#Choices: 'DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL'
LOGGING_LEVEL = 'ERROR'

#The number of events to serve in a feed
MAX_EVENTS_FEED = 10
#The number of events to retain for linking purposes
MAX_EVENTS_TOTAL = 100
#The maximum age of an event that can be included in a feed
MAX_AGE = 60 * 60 * 24

#Whether feed items should be removed when the system is reinitialised
CLEAR_ON_REINIT = True

#The name to give the feed
FEED_TITLE = config.SYSTEM_NAME

#The path at which individual records will be served
PATH_RECORD = '/ca/uguu/puukusoft/staticDHCPd/contrib/feedservice/record'

#The path at which to serve Atom (None to disable)
PATH_ATOM = '/ca/uguu/puukusoft/staticDHCPd/contrib/feedservice/atom'

#Whether feeds should be advertised in the web interface's headers
ADVERTISE = True

#The ID that uniquely identifies this feed
#If you are running multiple instances of staticDHCPd in your environment,
#you MUST generate a new feed-ID for EACH server. To do this, execute the
#following code in Python:
#import uuid; str(uuid.uuid4())
FEED_ID = 'bcd2dbbc-105b-4533-bb6d-01c2333cc55e'

#Do not touch anything below this line
################################################################################
import collections
import datetime
import logging
import time
import traceback
import uuid
import xml.etree.ElementTree as ET

_logger = logging.getLogger('contrib.feedservice')

_SERVER_ROOT = SERVER_BASE + '/'
_RECORD_URI = SERVER_BASE + PATH_RECORD + "?uid=%(uid)s"

_last_update = int(time.time())

_Event = collections.namedtuple('Event', ('summary', 'severity', 'timestamp', 'module', 'line', 'uid'))

class _FeedHandler(logging.Handler):
    """
    A handler that holds a fixed number of records, allowing index-based
    retrieval.
    """
    def __init__(self, capacity):
        logging.Handler.__init__(self)
        self._records = collections.deque(maxlen=capacity)
        
    def emit(self, record):
        global _last_update
        _last_update = int(record.created)
        self.acquire()
        try:
            self._records.appendleft((record, str(uuid.uuid4())))
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
        
    def presentRecord(self, path, queryargs, mimetype, data, headers):
        """
        Non-Handler method: renders the requested record for the web interface.
        """
        uids = queryargs.get('uid')
        if uids:
            uid = uids[0]
        else:
            return '<span class="error">No UID specified</span>'
            
        record = None
        self.acquire()
        try:
            #This should, in general, be efficient enough
            #The overhead of a dictionary seems unnecessary for all practical
            #use-cases
            for (record, uuid) in self._records:
                if uuid == uid:
                    break
            else:
                return '<span class="warn">Specified UID was not found; record may have expired</span>'
        finally:
            self.release()
            
        return self.format(record)
        
    def enumerateRecords(self, limit):
        """
        Non-Handler method: Enumerates every tracked record, up to `limit`.
        """
        events = []
        self.acquire()
        try:
            for i in xrange(min(limit, len(self._records))):
                (record, uid) = self._records[i]
                events.append(_Event(record.msg, record.levelname, record.created, record.name, record.lineno, uid))
        finally:
            self.release()
        return events
        
def _format_title(element):
    """
    Formats the given `element`, returning a string suitable for display in a
    feed's header.
    """
    return "%(severity)s at %(time)s in %(module)s:%(line)i" % {
     'severity': element.severity,
     'time': time.ctime(element.timestamp),
     'module': element.module,
     'line': element.line,
    }
    
def _feed_presenter(feed_type):
    """
    A decorator that handles exceptions.
    """
    def decorator(f):
        def function(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except Exception:
                _logger.error("Unable to render %(type)s feed:\n%(error)s" % {
                 'type': feed_type,
                 'error': traceback.format_exc(),
                })
                raise
        return function
    return decorator
    
_ATOM_ID_FORMAT = 'urn:uuid:%(id)s'
_FEED_ID = _ATOM_ID_FORMAT % {'id': FEED_ID}
@_feed_presenter('Atom')
def _present_atom(logger):
    """
    Assembles an Atom-compliant feed, drawing elements from `logger`.
    """
    feed = ET.Element('feed')
    feed.attrib['xmlns'] = 'http://www.w3.org/2005/Atom'
    
    title = ET.SubElement(feed, 'title')
    title.text = FEED_TITLE
    link = ET.SubElement(feed, 'link')
    link.attrib['href'] = _SERVER_ROOT
    updated = ET.SubElement(feed, 'updated')
    updated.text = datetime.datetime.fromtimestamp(_last_update).isoformat()
    id = ET.SubElement(feed, 'id')
    id.text = _FEED_ID
    
    global _ATOM_ID_FORMAT
    max_age = time.time() - MAX_AGE
    for element in logger.enumerateRecords(MAX_EVENTS_FEED):
        if element.timestamp < max_age: #Anything after this is also too old
            break
            
        entry = ET.SubElement(feed, 'entry')
        
        title = ET.SubElement(entry, 'title')
        title.text = _format_title(element)
        link = ET.SubElement(entry, 'link')
        link.attrib['href'] = _RECORD_URI % {'uid': element.uid}
        id = ET.SubElement(entry, 'id')
        id.text = _ATOM_ID_FORMAT % {'id': element.uid}
        updated = ET.SubElement(entry, 'updated')
        updated.text = datetime.datetime.fromtimestamp(element.timestamp).isoformat()
        summary = ET.SubElement(entry, 'summary')
        summary.text = element.summary
    return ('application/atom+xml', '<?xml version="1.0" encoding="utf-8"?>' + ET.tostring(feed))
    
#Setup happens here
################################################################################
_LOGGER = _FeedHandler(MAX_EVENTS_TOTAL)
_logger.info("Prepared feed-handler")
_LOGGER.setFormatter(logging.Formatter("""%(asctime)s : %(levelname)s : %(name)s:%(lineno)d[%(threadName)s]
<br/><br/>
%(message)s"""))
_LOGGER.setLevel(getattr(logging, LOGGING_LEVEL))
_logger.info("Feed-handler logging-level set to %(level)s" % {
 'level': LOGGING_LEVEL,
})
_logger.root.addHandler(_LOGGER)

if CLEAR_ON_REINIT:
    _logger.info("Registering callback handler to clear feeds on reinitialisation...")
    config.callbacks.systemAddReinitHandler(_LOGGER.flush)
    
_logger.info("Registering record-access-point at '%(path)s'..." % {
 'path': PATH_RECORD,
})
config.callbacks.webAddMethod(PATH_RECORD, _LOGGER.presentRecord, display_mode=config.callbacks.WEB_METHOD_TEMPLATE)

if PATH_ATOM:
    _logger.info("Registering Atom feed at '%(path)s'..." % {
     'path': PATH_ATOM,
    })
    config.callbacks.webAddMethod(
     PATH_ATOM, lambda *args, **kwargs: _present_atom(_LOGGER),
     display_mode=config.callbacks.WEB_METHOD_RAW
    )
    if ADVERTISE:
        _logger.info("Adding reference to Atom feed to headers...")
        atom_header = '<link href="' + PATH_ATOM + '" type="application/atom+xml" rel="alternate" title="' + config.SYSTEM_NAME + ' Atom"/>'
        config.callbacks.webAddHeader(lambda *args, **kwargs: atom_header)
        
