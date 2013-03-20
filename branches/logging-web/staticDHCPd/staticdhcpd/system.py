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

import databases

DATABASE = None

_reinitialisation_lock = threading.Lock()
_reinitialisation_callbacks = []

def initialise():
    global DATABASE
    DATABASE = databases.get_database()
    
def reinitialise():
    """
    Invokes every registered reinitialisation handler.
    """
    DATABASE.reinitialise()
    
    with _reinitialisation_lock:
        for callback in _reinitialisation_callbacks:
            callback()
            
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
            