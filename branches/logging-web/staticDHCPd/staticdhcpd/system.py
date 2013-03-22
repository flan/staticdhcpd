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

import config

_logger = logging.getLogger('system')

ALIVE = True #True until the system is ready to shut down.

_reinitialisation_lock = threading.Lock()
_reinitialisation_callbacks = []

_tick_lock = threading.Lock()
_tick_callbacks = []

_initialised = False
def initialise():
    #Avoid re-invocation.
    global _initialised
    if _initialised:
        return
    _initialised = True
    
    #Ready the database.
    import databases
    database = databases.get_database()
    registerReinitialisationCallback(database.reinitialise)
    
    if config.STATS_ENABLED:
        #Prepare the statistics engine.
        import statistics
        statistics_dhcp = statistics.DHCPStatistics()
        statistics.registerStatsCallback(statistics_dhcp.process)
        
    if config.WEB_ENABLED:
        #Start Webservice.
        import web
        webservice = web.WebService()
        webservice.start()
        
    #Start DHCP server.
    import dhcp
    dhcp = dhcp.DHCPService(database)
    dhcp.start()
    registerTickCallback(dhcp.tick)
    
def reinitialise():
    """
    Invokes every registered reinitialisation handler.
    
    @rtype: float
    @return: The number of seconds required to reinitialise the system.
    
    @raise Exception: Something went wrong; this is fatal.
    """
    start = time.time()
    with _reinitialisation_lock:
        for callback in _reinitialisation_callbacks:
            try:
                callback()
            except Exception:
                global ALIVE
                ALIVE = False
                _logger.critical("System shutdown triggered by unhandled exception:\n" + traceback.format_exc())
                raise
    return time.time() - start
    
def registerReinitialisationCallback(func):
    """
    Allows for modular registration of reinitialisation callbacks, to be invoked
    in the order of registration.
    
    @type func: callable
    @param func: A callable that takes no arguments; if already present, it will
        not be registered a second time.
    """
    with _reinitialisation_lock:
        if func in _reinitialisation_callbacks:
            _logger.error("Callback %(callback)r is already registered" % {'callback': func,})
        else:
            _reinitialisation_callbacks.append(func)
            
def unregisterReinitialisationCallback(func):
    """
    Allows for modular unregistration of reinitialisation callbacks.
    
    @type func: callable
    @param func: A callable; if not present, this is a no-op.
    """
    with _reinitialisation_lock:
        try:
            _reinitialisation_callbacks.remove(func)
        except ValueError:
            _logger.error("Callback %(callback)r is not registered" % {'callback': func,})

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
                
def registerTickCallback(func):
    """
    Allows for modular registration of tick callbacks, to be invoked
    in the order of registration.
    
    @type func: callable
    @param func: A callable that takes no arguments; if already present, it will
        not be registered a second time. The given callable must not block for
        any significant amount of time.
    """
    with _tick_lock:
        if func in _tick_callbacks:
            _logger.error("Callback %(callback)r is already registered" % {'callback': func,})
        else:
            _tick_callbacks.append(func)
            
def unregisterTickCallback(func):
    """
    Allows for modular unregistration of tick callbacks.
    
    @type func: callable
    @param func: A callable; if not present, this is a no-op.
    """
    with _tick_lock:
        try:
            _tick_callbacks.remove(func)
        except ValueError:
            _logger.error("Callback %(callback)r is not registered" % {'callback': func,})
            
