# -*- encoding: utf-8 -*-
"""
staticDHCPd module: statistics

Purpose
=======
 Defines statistics-delegation methods and structures.
 
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
import traceback

_logger = logging.getLogger('statistics')

_stats_lock = threading.Lock()
_stats_callbacks = []

Statistics = collections.namedtuple("Statistics", (
 'source_address', 'mac', 'client_ip', 'subnet', 'serial', 'method', 'processing_time', 'processed', 'pxe',
))
"""
#REWRITE: does not include everything

@type source_address: tuple(2)
@param source_address: The (address:basestring, port:int) of the sender.
@type mac: libpydhcpserver.dhcp_types.mac.MAC
@param mac: If a DHCP packet, the MAC for which it was sent; None otherwise.
@type method: basestring|None
@param method: A DHCP method, or None if the packet was not DHCP-compliant.
@type processing_time: float
@param processing_time: The amount of time, in seconds, required for processing.
@type processed: bool
@param processed: Whether the packet was processed or discarded for any reason.
`pxe` indicates whether the request arrived via PXE.

client_ip is an IPv4
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
                
def registerStatsCallback(callback):
    """
    Allows for modular registration of statistics callbacks, to be invoked
    in the order of registration.
    
    @type callback: callable
    @param callback: A callable that takes L{Statistics} as its argument; if already
        present, it will not be registered a second time. This function must not
        block for any significant amount of time.
    """
    with _stats_lock:
        if callback in _stats_callbacks:
            _logger.error("Callback %(callback)r is already registered" % {'callback': callback,})
        else:
            _stats_callbacks.append(callback)
            _logger.debug("Registered stats-callback %(callback)r" % {'callback': callback,})
            
def unregisterStatsCallback(callback):
    """
    Allows for modular unregistration of stats callbacks.
    
    @type callback: callable
    @param callback: A callable; if not present, this is a no-op.
    """
    with _stats_lock:
        try:
            _stats_callbacks.remove(callback)
            _logger.debug("Unregistered stats-callback %(callback)r" % {'callback': callback,})
        except ValueError:
            _logger.error("Callback %(callback)r is not registered" % {'callback': callback,})
            
