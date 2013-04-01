# -*- encoding: utf-8 -*-
"""
staticDHCPd package: databases

Purpose
=======
 Provides implementations for communication with all databases staticDHCPd can
 use.
 
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
from .. import config
from _generic import Database

def get_database():
    """
    Assembles and returns a database-interface object.
    
    @rtype: _generic.Database
    @return A database interface, usable to access DHCP information.
    """
    if callable(config.DATABASE_ENGINE):
        return config.DATABASE_ENGINE()
        
    if config.DATABASE_ENGINE == 'SQLite':
        from _sql import SQLite
        return SQLite()
    elif config.DATABASE_ENGINE == 'PostgreSQL':
        from _sql import PostgreSQL
        return PostgreSQL()
    elif config.DATABASE_ENGINE == 'MySQL':
        from _sql import MySQL
        return MySQL()
    elif config.DATABASE_ENGINE == 'Oracle':
        from _sql import Oracle
        return Oracle()
    elif config.DATABASE_ENGINE == 'INI':
        from _ini import INI
        return INI()
        
    raise ValueError("Unknown database engine: %(engine)s" % {
     'engine': config.DATABASE_ENGINE
    })
