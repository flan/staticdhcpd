# -*- encoding: utf-8 -*-
"""
staticDHCPd module: statistics

Purpose
=======
 Defines a statistics-processing object to track the activity of the system.
 
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
import threading
import time

import config

_Histrogram = collections.namedtuple('Histogram', ('unknown',))

class DHCPStatistics(object):
    #TODO: Make this thing hold a histographic map of key statistics for some configurable amount of time, stored as a distillation of a configurable time-interval's worth of activity, so that a graph can be drawn on the web interface
    #And possibly exported as CSV data
    #This can be done by having every collection- and access-method check against a common timestamp value and build a chunk for the past minute if exceeded
    #As for graphing, a small visual of total number of packets processed should suffice
    #When there's a gap in all activity, a numm histogram should be generated (None?) so that the collection will be consistent
    #For CSV export, use the current time and subtract one quantisation interval for each line, to provide timestamps
    #Remember to subtract the request sub-classifications from the parent-type-count when they become known
    _histograph = None
    
    _lock = None
    
    _other_packets = 0
    _dhcp_packets = None
    _dhcp_processing_time = 0.0
    
    _current_histogram = None
    _histogram_start_time = None
    _activity = True
    
    def __init__(self):
        self._histograph = collections.deque((None for i in xrange(config.STATS_RETENTION_COUNT)), maxlen=config.STATS_RETENTION_COUNT)
        
        self._dhcp_packets = {
         'DECLINE': 0,
         'DISCOVER': 0,
         'INFORM': 0,
         'REQUEST': 0,
         'REQUEST:INIT-REBOOT': 0,
         'REQUEST:REBIND': 0,
         'RELEASE': 0,
         'REQUEST:RENEW': 0,
         'REQUEST:SELECTING': 0,
        }
        
        self._lock = threading.Lock()
        
        self._initialiseHistogram()
        
    def _initialiseHistogram(self):
        """
        Must be called from a context in which the lock is held.
        """
        self._histogram_start_time = time.time()
        self._histogram_start_time -= self._histogram_start_time % config.STATS_QUANTISATION #Round down
        if self._activity:
            self._current_histogram = {
             'other-packets': 0,
             'dhcp-packets': {
              'DECLINE': 0,
              'DISCOVER': 0,
              'INFORM': 0,
              'REQUEST': 0,
              'REQUEST:INIT-REBOOT': 0,
              'REQUEST:REBIND': 0,
              'RELEASE': 0,
              'REQUEST:RENEW': 0,
              'REQUEST:SELECTING': 0,
             }
            }
            self._activity = False
            
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
                #Compile a Histogram tuple from the current histogram and store it
                pass
            else:
                self._histograph.append(None)
            self._initialiseHistogram()
            
    def trackDHCPPacket(self, packet_type):
        with self._lock:
            self._dhcp_packets[packet_type] += 1
            self._current_histogram['dhcp-packets'][packet_type] += 1
            
    def trackOtherPacket(self):
        with self._lock:
            self._other_packets += 1
            
    def trackProcessingTime(self, time_taken):
        with self._lock:
            self._dhcp_processing_time += time_taken
            
"""
def getStats(self):
        with self._stats_lock:
            for i in range(len(self._ignored_addresses)):
                self._ignored_addresses[i][1] -= config.POLLING_INTERVAL
            self._ignored_addresses = [address for address in self._ignored_addresses if address[1] > 0]
            
            stats = (self._packets_processed, self._packets_discarded, self._time_taken, len(self._ignored_addresses))
            
            self._packets_processed = 0
            self._packets_discarded = 0
            self._time_taken = 0.0
            if config.ENABLE_SUSPEND:
                self._dhcp_assignments = {}
                
            return stats
            
            
"""
    
"""
_POLL_RECORDS_LOCK = threading.Lock() #: A lock used to synchronize access to the stats-log.
_POLL_RECORDS = [] #: The stats-log.



def writePollRecord(packets, discarded, time_taken, ignored_macs):
    global _POLL_RECORDS
    
    with _POLL_RECORDS_LOCK:
        _POLL_RECORDS = [(time.time(), packets, discarded, time_taken, ignored_macs)] + _POLL_RECORDS[:config.POLL_INTERVALS_TO_TRACK - 1]
        
def readPollRecords():
    with _POLL_RECORDS_LOCK:
        return tuple(_POLL_RECORDS)
        
def logToDisk():
    try:
        log_file = None
        if config.LOG_FILE_TIMESTAMP:
            log_file = open(config.LOG_FILE + time.strftime(".%Y%m%d%H%M%S"), 'w')
        else:
            log_file = open(config.LOG_FILE, 'w')
            
        log_file.write("Summary generated %(time)s\n" % {'time': time.asctime(),})
        
        log_file.write("\nStatistics:\n")
        for (timestamp, packets, discarded, time_taken, ignored_macs) in readPollRecords():
            if packets:
                turnaround = time_taken / packets
            else:
                turnaround = 0.0
            log_file.write("%(time)s : received: %(received)i; discarded: %(discarded)i; turnaround: %(turnaround)fs/pkt; ignored MACs: %(ignored)i\n" % {
             'time': time.ctime(timestamp),
             'received': packets,
             'discarded': discarded,
             'turnaround': turnaround,
             'ignored': ignored_macs,
            })
            
        log_file.write("\nEvents:\n")
        for (timestamp, line) in readLog():
            log_file.write("%(time)s : %(line)s\n" % {
             'time': time.ctime(timestamp),
             'line': line,
            })
            
        log_file.close()
        
        return True
    except Exception, e:
        writeLog('Writing to disk failed: %(error)s' % {'error': str(e),})
        return False
"""