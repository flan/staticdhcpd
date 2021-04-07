# -*- encoding: utf-8 -*-
"""
staticdhcpdlib.system
=====================
Provides a centralised gathering point for system-level resources.
 
Legal
-----
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

(C) Neil Tallim, 2021 <neil.tallim@linux.com>
"""
import logging
import threading
import time
import traceback

_logger = logging.getLogger('system')

ALIVE = True #: True until the system is ready to shut down.

_reinitialisation_lock = threading.Lock()
_reinitialisation_callbacks = []

_tick_lock = threading.Lock()
_tick_callbacks = []
    
def reinitialise():
    """
    Invokes every registered reinitialisation handler.
    
    :return float: The number of seconds required to complete the operation.
    :except Exception: A callback failed to handle the reinitilisation request;
                       this exception may be logged, but the system treats this
                       as a fatal condition and will shut down.
    """
    start = time.time()
    _logger.warn("System reinitilisation commencing...")
    with _reinitialisation_lock:
        for callback in _reinitialisation_callbacks:
            try:
                callback()
            except Exception:
                global ALIVE
                ALIVE = False
                _logger.critical("System shutdown triggered by unhandled exception:\n{}".format(traceback.format_exc()))
                raise
    _logger.warn("System reinitilisation complete")
    return time.time() - start
    
def registerReinitialisationCallback(callback):
    """
    Registers a reinitialisation callback.
    
    :param callable callback: A callable that takes no arguments; if already
                              present, it will not be registered a second time.
    """
    with _reinitialisation_lock:
        if callback in _reinitialisation_callbacks:
            _logger.error("Callback {!r} is already registered".format(callback))
        else:
            _reinitialisation_callbacks.append(callback)
            _logger.debug("Registered reinitialisation {!r}".format(callback))
            
def unregisterReinitialisationCallback(callback):
    """
    Unregisters a reinitialisation callback.
    
    :param callable callback: The callback to remove.
    :return bool: True if a callback was removed.
    """
    with _reinitialisation_lock:
        try:
            _reinitialisation_callbacks.remove(callback)
        except ValueError:
            _logger.error("Callback {!r} is not registered".format(callback))
            return False
        else:
            _logger.debug("Unregistered reinitialisation {!r}".format(callback))
            return True

def tick():
    """
    Invokes every registered tick handler.
    """
    with _tick_lock:
        for callback in _tick_callbacks:
            try:
                callback()
            except Exception:
                _logger.critical("Unable to process tick-callback:\n{}".format(traceback.format_exc()))
                
def registerTickCallback(callback):
    """
    Registers a tick callback. Tick callbacks are invoked approximately once per
    second, but should treat this as a wake-up, not a metronome, and query the
    system-clock if performing any time-sensitive operations.
    
    :param callable callback: A callable that takes no arguments; if already
                              present, it will not be registered a second time.
                              The given callable must not block for any
                              significant amount of time.
    """
    with _tick_lock:
        if callback in _tick_callbacks:
            _logger.error("Callback {!r} is already registered".format(callback))
            _logger.debug("Registered tick {!r}".format(callback))
        else:
            _tick_callbacks.append(callback)
            
def unregisterTickCallback(callback):
    """
    Unregisters a tick callback.
    
    :param callable callback: The callback to remove.
    :return bool: True if a callback was removed.
    """
    with _tick_lock:
        try:
            _tick_callbacks.remove(callback)
        except ValueError:
            _logger.error("Callback {!r} is not registered".format(callback))
            return False
        else:
            _logger.debug("Unregistered tick {!r}".format(callback))
            return True
            
