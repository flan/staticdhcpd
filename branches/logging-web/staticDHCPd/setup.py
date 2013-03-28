#!/usr/bin/env python
"""
Deployment script for staticDHCPd.
"""
from distutils.core import setup
import platform

from staticdhcpdlib import VERSION

setup(
 name = 'staticDHCPd',
 version = VERSION,
 description = "Highly customisable, static-lease-focused DHCP server",
 author = 'Neil Tallim',
 author_email = 'flan@uguu.ca',
 license = 'GPLv3',
 url = 'http://staticdhcpd.googlecode.com/',
 packages = [
  'staticdhcpdlib',
  'staticdhcpdlib.databases',
  'staticdhcpdlib.web',
 ],
 data_files = [
  ('/etc/staticDHCPd', [
   'conf/conf.py.sample',
  ]),
 ],
 scripts = [
  'staticDHCPd',
 ],
)

#Post-installation stuff
instructions = [
"",
"",
"Before you can run 'staticDHCPd', which should now be in PATH, you must copy",
"/etc/staticDHCPd/conf.py.sample to /etc/staticDHCPd/conf.py and configure it",
"",
"Perform the following tasks to configure staticDHCPd to launch on system startup",
]
if platform.linux_distribution()[0] in ('Debian', 'Ubuntu', 'Mint',):
    instructions.extend([
"Debian-like (" + platform.linux_distribution()[0] + ":" + platform.linux_distribution()[1] + ")",
"\tCopy samples/staticDHCPd to /etc/init.d/staticDHCPd",
"\tRun '/bin/chmod a+x /etc/init.d/staticDHCPd'",
"\tRun '/usr/sbin/update-rc.d staticDHCPd defaults'",
    ])
elif platform.mac_ver()[0]:
    instructions.extend([
"OS X",
"\tCopy samples/ca.uguu.puukusoft.staticdhcpd.plist to /Library/LaunchDaemons/"
    ])
else:
    instructions.extend([
"Instructions relevant to your platform are unavailable; please contribute documentation",
    ])

for i in instructions:
    print(i)
