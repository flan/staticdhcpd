# -*- encoding: utf-8 -*-
"""
staticDHCPd module: system

Purpose
=======
 Provides a centralised gathering point for system-level resources.
 
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
import logging
import threading
import time
import traceback

_logger = logging.getLogger('system')

ALIVE = True #True until the system is ready to shut down.

_reinitialisation_lock = threading.Lock()
_reinitialisation_callbacks = []

_tick_lock = threading.Lock()
_tick_callbacks = []
    
def reinitialise():
    """
    Invokes every registered reinitialisation handler.
    
    The time taken to complete the operation is returned as a floating-point
    number of seconds.
    
    If an exception is unhandled by a callback, the system will shut down and
    the exception will be re-raised.
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
                _logger.critical("System shutdown triggered by unhandled exception:\n" + traceback.format_exc())
                raise
    _logger.warn("System reinitilisation complete")
    return time.time() - start
    
def registerReinitialisationCallback(callback):
    """
    Allows for modular registration of reinitialisation callbacks, to be invoked
    in the order of registration.
    
    @type callback: callable
    @param callback: A callable that takes no arguments; if already present, it will
        not be registered a second time.
    """
    with _reinitialisation_lock:
        if callback in _reinitialisation_callbacks:
            _logger.error("Callback %(callback)r is already registered" % {'callback': callback,})
        else:
            _reinitialisation_callbacks.append(callback)
            _logger.debug("Registered reinitialisation %(callback)r" % {'callback': callback,})
            
def unregisterReinitialisationCallback(callback):
    """
    Allows for modular unregistration of reinitialisation callbacks.
    
    @type callback: callable
    @param callback: A callable; if not present, this is a no-op.
    """
    with _reinitialisation_lock:
        try:
            _reinitialisation_callbacks.remove(callback)
            _logger.debug("Unregistered reinitialisation %(callback)r" % {'callback': callback,})
        except ValueError:
            _logger.error("Callback %(callback)r is not registered" % {'callback': callback,})

def tick():
    """
    Invokes every registered tick handler.
    """
    with _tick_lock:
        for callback in _tick_callbacks:
            try:
                callback()
            except Exception:
                _logger.critical("Unable to process tick-callback:\n" + traceback.format_exc())
                
def registerTickCallback(callback):
    """
    Allows for modular registration of tick callbacks, to be invoked
    in the order of registration.
    
    @type callback: callable
    @param callback: A callable that takes no arguments; if already present, it will
        not be registered a second time. The given callable must not block for
        any significant amount of time.
    """
    with _tick_lock:
        if callback in _tick_callbacks:
            _logger.error("Callback %(callback)r is already registered" % {'callback': callback,})
            _logger.debug("Registered tick %(callback)r" % {'callback': callback,})
        else:
            _tick_callbacks.append(callback)
            
def unregisterTickCallback(callback):
    """
    Allows for modular unregistration of tick callbacks.
    
    @type callback: callable
    @param callback: A callable; if not present, this is a no-op.
    """
    with _tick_lock:
        try:
            _tick_callbacks.remove(callback)
            _logger.debug("Unregistered tick %(callback)r" % {'callback': callback,})
        except ValueError:
            _logger.error("Callback %(callback)r is not registered" % {'callback': callback,})
            