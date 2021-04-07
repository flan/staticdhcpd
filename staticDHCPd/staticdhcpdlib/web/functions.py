# -*- encoding: utf-8 -*-
"""
staticdhcpdlib.web.functions
============================
Provides functions required to transform content for web-presentation.
 
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
import html

def sanitise(string):
    """
    Ensures that the string is usable anywhere in an HTML5 body.
    
    :param basestring string: The string to sanitise.
    :return basestring: The sanitised string, or None if nothing was provided.
    """
    return string and html.escape(string).replace('"', '&quot;')
    
