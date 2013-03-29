# -*- encoding: utf-8 -*-
"""
staticDHCPd module: web._functions

Purpose
=======
 Provides functions required to transform content for web-presentation.
 
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
import cgi

def sanitise(string):
    """
    `Ensures that the string, if not None or empty, is usable anywhere in an
    HTML5 body.
    """
    return string and cgi.escape(string).replace('"', '&quot;')
    