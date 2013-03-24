# -*- encoding: utf-8 -*-
"""
staticDHCPd module: web.resources

Purpose
=======
 Provides static content for the web-module.
 
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

CSS = """

"""

#for i in textwrap.wrap(<binary-read-from-file>, expand_tabs=False, replace_whitespace=False, drop_whitespace=False, width=40): print ' ' + repr(i)
FAVICON = (
 '\x00\x00\x01\x00\x01\x00  \x00\x00\x01\x00\x08\x00\xa8\x08\x00\x00\x16\x00\x00\x00(\x00\x00\x00 \x00\x00\x00@\x00\x00\x00\x01\x00\x08\x00\x00\x00'
 '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x06\x00\x00\x02\x00\x00\x05\x02\x00\x00\x07\x01'
 '\x04\x00\t\x03\x07\x00\x10\x04\x03\x00\n\x02\x0e\x00\x16\x05\x00\x00\x11\x03\x0c\x00\r\x02\x15\x00\x1f\x06\x03\x00\x17\x05\n'
 '\x00\x13\x03\x13\x00\x1c\x06\x07\x00\x0e\x02\x1a\x00\x18\x04\x12\x00\x18\x03\x17\x00\x1c\x05\x0f\x00!\x06\x0c'
 '\x00\x15\x04\x19\x00\x11\x03\x1f\x00\x16\x03\x1e\x00\x1d\x05\x15\x00\x1a\x04\x1c\x00"\x06\x13\x00\x18\x02%\x00\x1f\x05\x1b\x00\x1b\x04 '
 '\x00\'\x08\x10\x000\t\x0c\x00 \x05\x1f\x00\x18\x05"\x00\'\x0b\n\x00#\x07\x19\x00%\x05!\x00(\x08\x16\x00!\x05#\x00,\t'
 '\x12\x00\x1d\x05%\x00\x1f\x04)\x00%\x07\x1d\x00\x1b\x04+\x00-\x0e\x05\x00#\x05(\x00*\t\x1b\x00!\x04/\x00.\n\x18\x00 '
 "\x036\x00\x1d\x038\x00)\x07'\x00\x1e\x052\x003\x0c\x14\x00,\t!\x000\n"
 "\x1e\x00*\x0e\x13\x00'\x06/\x00.\x08&\x00)\x03=\x00:\r\x17\x003\n$\x00-\x08/\x00.\x04=\x007\r"
 '\x1c\x00;\x10\x11\x00&\x084\x002\t-\x00/\x075\x008\x0c"\x00*\t3\x004\x083\x00!\x0b'
 '1\x003\x11\x17\x004\x0e!\x00>\x0e\x1f\x00-\x089\x00-\x0c,\x00)\x08;\x00,\x06A\x00$\x06D\x005\r'
 "'\x00>\x10\x1a\x00<\x0c)\x008\x0c-\x00D\x12\x16\x00!\x0b:\x005\x08?\x002\x08A\x00(\x06L\x00<\x10&\x00<\x0c"
 '5\x00L\x13\x19\x00G\x12\x1f\x004\x0c:\x00<\x14\x1d\x00;\x0b'
 '>\x00C\x12$\x00.\x08M\x00G\x15\x19\x00;\x11,\x00B\x0e4\x002\tK\x000\x0bF\x00E\x11+\x00C\x15\x1f\x00?\n'
 'F\x007\nJ\x00>\x08O\x009\rC\x006\x06\\\x00C\x120\x00<\x0cI\x00N\x120\x00<\x11<\x008\n'
 'U\x00H\x14.\x00M\x15*\x00F\x127\x00R\x16&\x00<\x0bT\x00@\x145\x00C\x18(\x00M\x18%\x001\x0c'
 'Z\x00L\x146\x00A\x11D\x00I\x12?\x00U\x16/\x00G\x10H\x00D\x10K\x00;\x14B\x00F\x13C\x00O\x14=\x00B\x0c'
 "]\x00P\x1c#\x00R\x19/\x00S\x185\x00]\x1c'\x00W\x1d&\x00G\x0ce\x00M\x16C\x00?\x0fa\x00Y\x1c-\x00H\x10"
 ']\x00F\x12W\x00S\x18A\x00O\x1f+\x00_\x1e*\x00Z\x1f)\x00[\x1e0\x00X\x1c:\x00W /\x00b\x1e2\x00^\x1d'
 '7\x00H\x0er\x00b"&\x00T\x18M\x00P\x1e=\x00c!-\x00h"(\x00P\x19Q\x00Z\x1bM\x00j$*\x00f!'
 "6\x00Y\x1eH\x00V%2\x00a#5\x00U',\x00]!?\x00]%5\x00\\'/\x00g%2\x00j!?\x00U\x14"
 "r\x00e!C\x00V\x17j\x00c'1\x00e#>\x00_%<\x00u%7\x00o&6\x00k%;\x00a\x1ag\x00c#"
 'I\x00b\x1fX\x00s&?\x00p$J\x00s)9\x00g#R\x00F\x17\x86\x00n"U\x00z+6\x00j#Y\x00p*'
 '@\x00n&P\x00v-6\x00G\x18\x91\x00s*H\x00D\x1a\x95\x00u.E\x00|-G\x00\x800<\x00k(a\x00\x870'
 '>\x00y,S\x00N\x1c\x9e\x00}4>\x00x6=\x00\x856:\x00^\x1f\x9c\x00\x8e6E\x00\x887D\x00\x845O\x00~.'
 'i\x00\x83/f\x00\x821`\x00x-w\x00\x869L\x00\x8c;H\x00\x8e7U\x00\x917^\x00\x95>F\x00\x90;R\x00K&'
 '\xb3\x00\x96=N\x00\x8b@K\x00\x80?T\x00\x87@Q\x00\x83>[\x00\x8bA[\x00\x9dEN\x00\x99D[\x00p1\xaa\x00\x99<'
 'x\x00\x9bCb\x00\xaeIN\x00\x98?\x7f\x00\x9eLS\x00\x96Du\x00\xa7Ie\x00\xa7L_\x00\xa7Pi\x00\x86B\xa4\x00\x96O'
 '\x81\x00u=\xcd\x00\xb6Ty\x00\x87H\xd4\x00\xb0Z\xa0\x00\xcdf\x80\x00\x96O\xec\x00\x9eR\xe3\x00\xaeb\xcd\x00\xa0h\xdc\x00\xb2h'
 '\xdd\x00\xb1e\xec\x00\x00\x00\x00\x00\x02\x02\x02\x02\x05\x02\x03\x05\x02\x01\x03\x02\x01\x01\x05\x02\x05\x05\x01\x01\x04\x02\x02\x02\x05\x05\x02\x02\x05\x02'
 '\x04\x04\x05\x03\x05\x02\x02\x05\x02\x02\x01\x02\x01\x06\x08\x06\x03\x03\x02\t\x0c'
 '\x0e\x06\x03\x02\x04\x02\x02\x02\x03\x02\x02\x02\x02\x02\x02\x02\x02\x05\x02\x02\x03\x03\x12$\x12\x05\x05\x07\x05\x06\r'
 '.W\x13!\x0e\x06\x01\x04\x04\x05\x02\x04\x04\x02\x02\x02\x01\x02\x02\x03\x01\x06}8\x10\x05\r(\x14\x03\x07\t\x16a\x05\x06\x0e"\x0c'
 '\x02\x02\x02\x05\x02\x02\x02\x01\x05\x05\x03\x01\x02"\x90e\r\x07\x07\t\t1\x06 \r e\t\x06\x05\x07K5\x03\x02\x02\x02\x04\x02\x02'
 "\x02\x02\x02\x02-iw=\x14\x1a\x07\x05\x05\x15'\x06\x17SoE\x07\x05\x06\x11\x8d,\x05\x02\x04\x02\x02\x02\x03\x02\x02\x14F#Z5"
 'M%\x1c\x06\x06\x05#\x85]|9\t\x05\x06\x06\x14a%#\x03\x04\x02\x02\x05\x02\x05\x05j,!TYjm\x07\x07\x05\t\n'
 '4\x8e\x95S\x1b\x12\x0c\tIKM.2\x02\x02\x02\x05\x02\x03%5I/\\\xa4!-\x19\t'
 '\x06\x06\x05\x0e\xd0\xc2qK"\x1c\x18\x87L\x14\x108\x06\x02\x02\x02\x03\t=K#7h\xb9)&@\x13\x07\x05\x03\x05\xc7\xca9l'
 '\x17\x10}\xb2\x1a\x1d\x19\x1b\x1f\x02\x02\x02\x02Mwj.7@\xba\xd8h\x8aL\x0e\t\x05\x05\xaa\xb7-2\t'
 '\x12\xbc\xb6\x8cR2N\x1f\x03\x02\x01\x03>=R\x9e\x87^\xaa\xdbh\xb0\x92\x10\x08\x03\t\xb2hI\x08\x0c'
 "\xb1\xc5\x8e|R\x9a'(\x11\x02\x02\x14M\t\x1f\x0c\x84\x9c/c\xda\x1d\xe1\x12\x0c\x05\x17\xa5\xc3Z\x12\x86\xd9\xc5\x89gB5\x128"
 '\r\x02\x02\x1aM2\x8fs\x95\xd7\xa4\t'
 "\x12\xa5\xa7\xe4G\x06(\xe3\xc1q\xe2\xf0\xe6\xbb?%\x1b&-,\x10\x05\x02\x14\x10'KFQp\xec\xc3y7\xaa\xfc\n"
 '\x07\xdf\xfa\xf7\xf8\xe7\xce\xb1\x8cS\x06\x0e\x19\x0c'
 '(a\x04\x053Xf77&\x13\x83\xf0\xda\xce\xf3{\x06\x03U\xc6\xf9\xea\xc1\xab\xb1g\x87\xb7\x99\xa0\x83oo\x07\x02\t'
 "\x11\x11\x06\x06\r\x07)\xac\xd3\xab\xc7'\x05\x02\x05{\xe8\xee\xd9\xda\xdb\xb9\x8a|\\;5,W\x06\x02\x05\x07,\x14\t\x0c"
 '\x13c\x99\xd0\xd0\xc3\xf6\xbd*\xcd\xc4\xfb\xf1\xda\xda\xc1\xd7\xae\\~J2\t\x17\x05\x02\t8\x12\x12\x10C;\x83\x8e\x93\x9e\xab\xe5\xfd'
 '\xf4\xfe\xf2\x9d\x95z\x87|QdZ\x8b\x1f\x0eKK\x05\x02\x06WoFz\x95\xcc\xd7\x9f\xa2\x9b\xab\xbb\xe6\xd9\xe3\xed\xf1\x97\x96\x82\x06'
 '\r3\x0e\x17\x13\t\x1c)\x03\x04\x03V\x8dCSg\x87\x93\xc3\xc3\xbf\xcb\xd2\xde\x9e\xcf\xc7\xd9\xf5\xd3\xb5\\7\x03\x04\x0c\x11\t\x0c\x0b'
 '\x02\x02\x04\x17K6&\x1dv\x98\\T\xeb\xb9\xea\xb7b\xce\x9e\x9b\xd5\xe0\x93\x98\xa1|)\n\t\x10\x13\x05\x02\x02\x04\x05K\x17\x12T'
 '5\x1d\x06\xb0\x94\xc1z\x10H\xc3u\xbc\x88\xba`QbQ<gq"-\x02\x02\x05\x02\x02%]?\x19!"`\xe9\x96\xd4\x19\x17'
 "b\x98\x99\x87\x10#T\\D\\\x06\x11C>\x05\x02\x02\x02\x02\x02\x03F-6?\x84;\xc2\x91\xc5\x19P@st\x98S\x11'N"
 '~9-\t\x12!\x02\x02\x02\x05\x02\x02\x01\x07F\x90t\x1dY\xb8s\xa3)D$\\,b;\x12\x04\t'
 '\x06\xd1P"+\x02\x02\x02\x02\x02\x02\x05\x05\x02\x0c\xaf=\x0eJ|\x98?\x19$,\x8e\x17\x1e\x1beX\x06\x12\x0c'
 '#u\x03\x02\x02\x02\x02\x05\x02\x02\x02\x02\x04\x06$D\x8c\x80\xa12L\x0cm\x8f56\x12O8)\x10)\x12\x02\x02\x02\x02\x02\x02\x02'
 '\x02\x05\x02\x03\x02\x02\x04BWo\xad9K\x1b\x10\x8d=\x85)\x10\x19\x1f\x12\x06\x04\x02\x02\x02\x02\x02\x02\x02\x02\x02\x05\x04\x04\x02\x02\x02'
 '\t8o,#\x12\x0e#.\x1b22)\x06\x03\x02\x02\x02\x02\x03\x02\x02\x02\x05\x05\x05\x04\x02\x02\x02\x02\x03\x02\x02\x02\x07\x17\x13\x1d-'
 ')\x0e\x0c\x05\x02\x02\x03\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x03\x03\x03\x02\x02\x02\x02\x02\x02\x02'
 '\x02\x02\x02\x02\x02\x02\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
 '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
 '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
 '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
)