# -*- encoding: utf-8 -*-
"""
Processes and exposes runtime statistics information about the DHCP server.

To use this module, customise the constants below, then add the following to
conf.py's init() function:
    import stats
    
Like staticDHCPd, this module under the GNU General Public License v3
(C) Neil Tallim, 2013 <flan@uguu.ca>
"""
#The name of the module to which these elements belong
MODULE = 'stats'

#Whether lifetime stats should be made available
LIFETIME_STATS_ENABLED = True
#Whether lifetime stats should be included in the web dashboard
LIFETIME_STATS_DISPLAY = True
#The ordering-bias value to apply, as an integer; if None, appended to the end
LIFETIME_STATS_ORDERING = None
#If not available via the dashboard, they can be accessed at this path
LIFETIME_STATS_PATH = '/ca/uguu/puukusoft/staticDHCPd/contrib/stats/lifetime'
#The name of the component; if None and not displayed in the dashboard, the
#method link will be hidden
LIFETIME_STATS_NAME = 'lifetime'

#Whether averaging values should be made available
AVERAGES_ENABLED = True
#The periods, as quantised periods, over which statistics should be averaged
#0 represents the current frame
AVERAGES_WINDOWS = [0, 1, 2, 3, 12, 72, 288]
#Whether averages should be included in the web dashboard
AVERAGES_DISPLAY = True
#The ordering-bias value to apply, as an integer; if None, appended to the end
AVERAGES_ORDERING = None
#If not available via the dashboard, they can be accessed at this path
AVERAGES_PATH = '/ca/uguu/puukusoft/staticDHCPd/contrib/stats/averages'
#The name of the component; if None and not displayed in the dashboard, the
#method link will be hidden
AVERAGES_NAME = 'averages'

#Whether histograph generation should be made available
#This component depends on matplotlib
HISTOGRAPH_ENABLED = True
#Whether the histograph should be rendered in the web dashboard
HISTOGRAPH_DISPLAY = True
#The ordering-bias value to apply, as an integer; if None, appended to the end
HISTOGRAPH_ORDERING = None
#If not available via the dashboard, it can be accessed at this path
HISTOGRAPH_PATH = '/ca/uguu/puukusoft/staticDHCPd/contrib/stats/histograph'
#The name of the component; if None and not displayed in the dashboard, the
#method link will be hidden
HISTOGRAPH_NAME = 'histograph'
#The path at which a CSV version of the histograph may be obtained; None to
#disable
HISTOGRAPH_CSV_PATH = '/ca/uguu/puukusoft/staticDHCPd/contrib/stats/histograph.csv'
#The name of the component; if None, the method link will be hidden
HISTOGRAPH_CSV_NAME = 'histograph (csv)'

#The number of seconds over which to quantise data
#Lower values will increase resolution, but consume more memory
QUANTISATION_INTERVAL = 60 * 5

#The number of quantised elements to retain for statistical evaluation
#Higher values will increase the amount of data that can be interpreted,
#at the cost of more memory and processing time
RETENTION_COUNT = 288 * 2 #At five minutes, 288 is a day

#Do not touch anything below this line
################################################################################
import collections
import logging
import threading
import time

from staticdhcpdlib import config
from staticdhcpdlib import dhcp
_METHODS = tuple(sorted(getattr(dhcp, key) for key in dir(dhcp) if key.startswith('_PACKET_TYPE_')))

_logger = logging.getLogger('contrib.stats')

_Histogram = collections.namedtuple('Histogram', (
 'dhcp_packets', 'dhcp_packets_discarded', 'other_packets', 'processing_time',
))

def _generate_dhcp_packets_dict():
    return dict((method, 0) for method in _METHODS)
    
class DHCPStatistics(object):
    _histograph = None
    
    _lock = None
    
    _other_packets = 0
    _dhcp_packets = None
    _dhcp_packets_discarded = None
    _processing_time = 0.0
    
    _current_histogram = None
    _histogram_start_time = None
    _activity = False
    
    def __init__(self):
        self._histograph = collections.deque((None for i in xrange(config.STATS_RETENTION_COUNT)), maxlen=config.STATS_RETENTION_COUNT)
        
        self._dhcp_packets = _generateDHCPPacketsDict()
        self._dhcp_packets_discarded = _generateDHCPPacketsDict()
        
        self._lock = threading.Lock()
        
        self._initialiseHistogram()
        
    def _initialiseHistogram(self):
        """
        Must be called from a context in which the lock is held.
        """
        self._histogram_start_time = time.time()
        self._histogram_start_time -= self._histogram_start_time % config.STATS_QUANTISATION #Round down
        self._current_histogram = {
         'other-packets': 0,
         'dhcp-packets': _generateDHCPPacketsDict(),
         'dhcp-packets-discarded': _generateDHCPPacketsDict(),
         'processing-time': 0.0,
        }
        
    def _updateHistograph(self):
        """
        Call this every time data is collected or requested.
        """
        with self._lock:
            current_time = time.time()
            if self._histogram_start_time <= current_time - config.STATS_QUANTISATION:
                #Insert null histograms as needed
                steps = int((current_time - self._histogram_start_time) / max(1, config.STATS_QUANTISATION))
                for i in range(1, steps):
                    self._histograph.append(None)
                    
                if self._activity:
                    self._histograph.append(_Histogram(
                     self._current_histogram['dhcp-packets'],
                     self._current_histogram['dhcp-packets-discarded'],
                     self._current_histogram['other-packets'],
                     self._current_histogram['processing-time']
                    ))
                    self._initialiseHistogram()
                    self._activity = False
                else:
                    self._histograph.append(None)
                    
    def process(self, statistics):
        """
        Updates the statstics engine with details about a packet.
        
        @type statistics: L{_Statistics}
        @param statistics: The processing result.
        """
        self._updateHistograph()
        with self._lock:
            if statistics.method:
                self._dhcp_packets[statistics.method] += 1
                self._current_histogram['dhcp-packets'][statistics.method] += 1
                if not statistics.processed:
                    self._dhcp_packets_discarded[statistics.method] += 1
                    self._current_histogram['dhcp-packets-discarded'][statistics.method] += 1
            else:
                self._other_packets += 1
                self._current_histogram['other-packets'] += 1
            self._processing_time += statistics.processing_time
            self._current_histogram['processing-time'] += statistics.processing_time
            
            
#TODO: Make this thing hold a histographic map of key statistics for some configurable amount of time, stored as a distillation of a configurable time-interval's worth of activity, so that a graph can be drawn on the web interface
#And possibly exported as CSV data
#This can be done by having every collection- and access-method check against a common timestamp value and build a chunk for the past minute if exceeded
#As for graphing, a small visual of total number of packets processed should suffice
#When there's a gap in all activity, a numm histogram should be generated (None?) so that the collection will be consistent
#For CSV export, use the current time and subtract one quantisation interval for each line, to provide timestamps
#Remember to subtract the request sub-classifications from the parent-type-count when they become known


http://41j.com/blog/2012/04/simple-histogram-in-pythonmatplotlib-no-display-write-to-png/

http://bespokeblog.wordpress.com/2011/07/11/basic-data-plotting-with-matplotlib-part-3-histograms/
    
    
    
    
    
    
    
    
    
    

"""
        Renders the current state of the memory-log as HTML for consumption by
        the client.
        try:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.send_header('Last-modified', time.strftime('%a, %d %b %Y %H:%M:%S %Z'))
            self.end_headers()
            
            self.wfile.write('<html><head><title>%(name)s log</title></head><body>' % {'name': config.SYSTEM_NAME,})
            self.wfile.write('<div style="width: 950px; margin-left: auto; margin-right: auto; border: 1px solid black;">')
            
            self.wfile.write('<div>Statistics:<div style="text-size: 0.9em; margin-left: 20px;">')
            for (timestamp, packets, discarded, time_taken, ignored_macs) in logging.readPollRecords():
                if packets:
                    turnaround = time_taken / packets
                else:
                    turnaround = 0.0
                self.wfile.write("%(time)s : received: %(received)i; discarded: %(discarded)i; turnaround: %(turnaround)fs/pkt; ignored MACs: %(ignored)i<br/>" % {
                 'time': time.ctime(timestamp),
                 'received': packets,
                 'discarded': discarded,
                 'turnaround': turnaround,
                 'ignored': ignored_macs,
                })
            self.wfile.write("</div></div><br/>")
            
            self.wfile.write('<div>Events:<div style="text-size: 0.9em; margin-left: 20px;">')
            for line in _web_logger.readContent():
                self.wfile.write("%(line)s<br/>" % {
                 'line': cgi.escape(line),
                })
            self.wfile.write("</div></div><br/>")
            
            self.wfile.write('<div style="text-align: center;">')
            self.wfile.write('<small>Summary generated %(time)s</small><br/>' % {
             'time': time.asctime(),
            })
            self.wfile.write('<small>%(server)s:%(port)i | PID: %(pid)i | v%(core_version)s | <a href="http://uguu.ca/" onclick="window.open(this.href); return false;">uguu.ca</a></small><br/>' % {
             'pid': os.getpid(),
             'server': config.DHCP_SERVER_IP,
             'port': config.DHCP_SERVER_PORT,
             'core_version': VERSION,
            })
            self.wfile.write('<form action="/" method="post"><div style="display: inline;">')
            self.wfile.write('<label for="key">Key: </label><input type="password" name="key" id="key"/>')
            if config.USE_CACHE:
                self.wfile.write('<input type="submit" value="Flush cache and write log to disk"/>')
            else:
                self.wfile.write('<input type="submit" value="Write log to disk"/>')
            self.wfile.write('</div></form>')
            self.wfile.write('</div>')
            
            self.wfile.write("</div></body></html>")
        except Exception:
            _logger.error("Problem while serving Response:\n" + traceback.format_exc())
"""

#Setup happens here
################################################################################

if staticdhcpdlib.config.STATS_ENABLED: #No point in turning this on without webservices
            _logger.info("Webservice statistics enabled; configuring...")
            import staticdhcpdlib.statistics
            import staticdhcpdlib.statistics.basic_engines
            statistics_dhcp = staticdhcpdlib.statistics.basic_engines.DHCPStatistics()
            staticdhcpdlib.statistics.registerStatsCallback(statistics_dhcp.process)