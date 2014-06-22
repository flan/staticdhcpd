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
 'source_address', 'mac', 'ip', 'subnet', 'serial', 'method', 'processing_time', 'processed', 'pxe',
))
"""
Statistics associated with a DHCP event.

.. py:attribute:: source_address

    An :class:`libpydhcpserver.dhcp.Address` containing the IP and port of the
    client.

.. py:attribute:: mac

    A :class:`libpydhcpserver.dhcp_types.mac.MAC` containing the MAC of the
    client; None if the event was not due to a DHCP packet.

.. py:attribute:: ip

    An :class:`libpydhcpserver.dhcp_types.ipv4.IPv4` containing the address
    assigned to the client, if any.

.. py:attribute:: subnet

    The database-subnet associated with this event.

.. py:attribute:: serial

    The database-serial associated with this event.

.. py:attribute:: method

    The DHCP method of the received packet.

.. py:attribute:: processing_time

    The number of seconds required to finish processing the event.

.. py:attribute:: processed

    Whether a response was generated (False if non-DHCP or blacklisted).

.. py:attribute:: pxe

    True if the request received was PXE.
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
            
