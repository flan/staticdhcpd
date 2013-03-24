# -*- encoding: utf-8 -*-
"""
staticDHCPd module: statistics.basic_engines

Purpose
=======
 Defines a statistics-processing module to track the activity of the system.
 
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
import threading
import time

from .. import config

from .. import dhcp
_PACKET_TYPES = tuple(sorted(getattr(dhcp, key) for key in dir(dhcp) if key.startswith('_PACKET_TYPE_')))

_logger = logging.getLogger('statistics.basic_engines')

_Histogram = collections.namedtuple('Histogram', (
 'dhcp_packets', 'dhcp_packets_discarded', 'other_packets', 'processing_time',
))

def _generateDHCPPacketsDict():
    return dict((packet_type, 0) for packet_type in _PACKET_TYPES)
    
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
                self._dhcp_packets[statistics.packet_type] += 1
                self._current_histogram['dhcp-packets'][statistics.packet_type] += 1
                if not statistics.processed:
                    self._dhcp_packets_discarded[statistics.packet_type] += 1
                    self._current_histogram['dhcp-packets-discarded'][statistics.packet_type] += 1
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
