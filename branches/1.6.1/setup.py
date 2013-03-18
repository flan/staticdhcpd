#!/usr/bin/env python
"""
Deployment script for staticDHCPd.
"""
from distutils.core import setup

from staticdhcpd import VERSION

setup(
 name = 'staticDHCPd',
 version = VERSION,
 description = "A static-lease-managing DHCP server",
 author = 'Neil Tallim',
 author_email = 'flan@uguu.ca',
 license = 'GPLv3',
 url = 'http://staticdhcpd.googlecode.com/',
 packages = [
  'staticdhcpd',
  'libpydhcpserver',
 ],
 data_files = [
  ('/etc/staticDHCPd', [
   'samples/conf.py.sample',
   'samples/dynamism.py.sample',
  ]),
 ],
 scripts = [
  'staticDHCPd',
 ],
)

#Post-installation stuff
for i in [
"Before you can run 'staticDHCPd', which should now be in PATH, you must copy",
"/etc/staticDHCPd/conf.py.sample to /etc/staticDHCPd/conf.py and configure it",
"",
"Perform the following tasks to configure staticDHCPd to launch on system startup",
"Debian/Ubuntu",
"\tCopy samples/staticDHCPd to /etc/init.d/staticDHCPd",
"\tRun '/bin/chmod a+x /etc/init.d/staticDHCPd'",
"\tRun '/usr/sbin/update-rc.d staticDHCPd defaults'",
"",
"OS X",
"\tCopy samples/ca.uguu.puukusoft.staticdhcpd.plist to the System Launch Library"
"\tThere's probably more to it; please contibute detailed steps"
]:
    print(i)
    