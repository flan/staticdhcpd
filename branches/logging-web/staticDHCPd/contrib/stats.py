# -*- encoding: utf-8 -*-
"""
Processes and exposes runtime statistics information about the DHCP server.

To use this module, customise the constants below, then add the following to
conf.py's init() function:
    import stats
    
Like staticDHCPd, this module under the GNU General Public License v3
(C) Neil Tallim, 2013 <flan@uguu.ca>
"""

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



The netbook defined additional config parameters, like whether the web
interface should display lifetime stats, and stats-averaging windows:
[0, 1, 2, 3, 4]
That would display average throughput in the current frame (0), the
past one frame, the past two frames, and so forth, all aggregated.

Of course, there also needs to be an option for rendering a histograph
and a pair for exposing a CSV download of the histograph.


http://41j.com/blog/2012/04/simple-histogram-in-pythonmatplotlib-no-display-write-to-png/


    
    
    
    
    
    
    
    
    
    

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