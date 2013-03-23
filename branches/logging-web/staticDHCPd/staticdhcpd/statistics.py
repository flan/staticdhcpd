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

_stats_lock = threading.Lock()
_stats_callbacks = []

Statistics = collections.namedtuple("Statistics", (
 'source_address', 'mac', 'method', 'processing_time', 'processed',
))
"""
@type source_address: tuple(2)
@param source_address: The (address:basestring, port:int) of the sender.
@type mac: basestring|None
@param mac: If a DHCP packet, the MAC for which it was sent; None otherwise.
@type method: basestring|None
@param method: A DHCP method, or None if the packet was not DHCP-compliant.
@type processing_time: float
@param processing_time: The amount of time, in seconds, required for processing.
@type processed: bool
@param processed: Whether the packet was processed or discarded for any reason.
"""

def emit(statistics):
    """
    Invokes every registered stats handler to deliver the new statistics
    information.
    
    @type statistics: Statistics
    @param statistics: The statistics to report.
    """
    with _stats_lock:
        for callback in _stats_callbacks:
            try:
                callback(statistics)
            except Exception:
                _logger.critical("Unable to deliver statistics:\n" + traceback.format_exc())
                
def registerStatsCallback(func):
    """
    Allows for modular registration of statistics callbacks, to be invoked
    in the order of registration.
    
    @type func: callable
    @param func: A callable that takes L{Statistics} as its argument; if already
        present, it will not be registered a second time. This function must not
        block for any significant amount of time.
    """
    with _stats_lock:
        if func in _stats_callbacks:
            _logger.error("Callback %(callback)r is already registered" % {'callback': func,})
        else:
            _stats_callbacks.append(func)
            
def unregisterStatsCallback(func):
    """
    Allows for modular unregistration of stats callbacks.
    
    @type func: callable
    @param func: A callable; if not present, this is a no-op.
    """
    with _stats_lock:
        try:
            _stats_callbacks.remove(func)
        except ValueError:
            _logger.error("Callback %(callback)r is not registered" % {'callback': func,})
            
            
_Histogram = collections.namedtuple('Histogram', (
 'dhcp_packets', 'dhcp_packets_discarded', 'other_packets', 'processing_time',
))

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
    _dhcp_packets_discarded = None
    _processing_time = 0.0
    
    _current_histogram = None
    _histogram_start_time = None
    _activity = False
    
    def __init__(self):
        self._histograph = collections.deque((None for i in xrange(config.STATS_RETENTION_COUNT)), maxlen=config.STATS_RETENTION_COUNT)
        
        self._dhcp_packets = {
         'DECLINE': 0,
         'DISCOVER': 0,
         'INFORM': 0,
         'RELEASE': 0,
         'REQUEST': 0,
         'REQUEST:INIT-REBOOT': 0,
         'REQUEST:REBIND': 0,
         'REQUEST:RENEW': 0,
         'REQUEST:SELECTING': 0,
        }
        self._dhcp_packets_discarded = {
         'DECLINE': 0,
         'DISCOVER': 0,
         'INFORM': 0,
         'RELEASE': 0,
         'REQUEST': 0,
         'REQUEST:INIT-REBOOT': 0,
         'REQUEST:REBIND': 0,
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
        self._current_histogram = {
         'other-packets': 0,
         'dhcp-packets': {
          'DECLINE': 0,
          'DISCOVER': 0,
          'INFORM': 0,
          'RELEASE': 0,
          'REQUEST': 0,
          'REQUEST:INIT-REBOOT': 0,
          'REQUEST:REBIND': 0,
          'REQUEST:RENEW': 0,
          'REQUEST:SELECTING': 0,
         },
         'dhcp-packets-discarded': {
          'DECLINE': 0,
          'DISCOVER': 0,
          'INFORM': 0,
          'RELEASE': 0,
          'REQUEST': 0,
          'REQUEST:INIT-REBOOT': 0,
          'REQUEST:REBIND': 0,
          'REQUEST:RENEW': 0,
          'REQUEST:SELECTING': 0,
         },
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
                self._dhcp_packets[packet_type] += 1
                self._current_histogram['dhcp-packets'][packet_type] += 1
                if not statistics.processed:
                    self._dhcp_packets_discarded[packet_type] += 1
                    self._current_histogram['dhcp-packets-discarded'][packet_type] += 1
            else:
                self._other_packets += 1
                self._current_histogram['other-packets'] += 1
            self._processing_time += statistics.processing_time
            self._current_histogram['processing-time'] += statistics.processing_time
            