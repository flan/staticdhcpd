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
import threading
import traceback

import config
import databases
import dhcp
import statistics
import web

ALIVE = True #True until the system is ready to shut down.

DATABASE = None
DHCP = None
STATISTICS_DHCP = None
WEBSERVICE = None

_reinitialisation_lock = threading.Lock()
_reinitialisation_callbacks = []

def initialise():
    #Ready the database.
    global DATABASE
    DATABASE = databases.get_database()
    registerReinitialisationCallback(DATABASE.reinitialise)
    
    #Prepare the statistics engine.
    global STATISTICS_DHCP
    STATISTICS_DHCP = statistics.DHCPStatistics()
    
    #Start Webservice.
    global WEBSERVICE
    if config.WEB_ENABLED:
        WEBSERVICE = web.WebService()
        WEBSERVICE.start()
    else:
        WEBSERVICE = web.WebServiceDummy()
        
    #Start DHCP server.
    global DHCP
    DHCP = dhcp.DHCPService()
    DHCP.start()
    
def reinitialise():
    """
    Invokes every registered reinitialisation handler.
    """
    with _reinitialisation_lock:
        for callback in _reinitialisation_callbacks:
            try:
                callback()
            except Exception:
                global ALIVE
                ALIVE = False
                _logger.critical("System shutdown triggered by unhandled exception:\n" + traceback.format_exc())
                raise
                
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
            #Log error
            pass
         else:
            _reinitialisation_callbacks.append(func)
            
def unregisterReinitialisationCallback(func):
    """
    Allows for modular unregistration of reinitialisation callbacks.
    
    @type func: callable
    @param func: A callable that takes no arguments; if not present, this is a
        no-op.
    """
    with _reinitialisation_lock:
        try:
            _reinitialisation_callbacks.remove(func)
        except ValueError:
            #log error
            pass
            