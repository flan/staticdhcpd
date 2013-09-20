#!/usr/bin/env python
"""
Deployment script for staticDHCPd.
"""
from distutils.core import setup
import os
import platform
import re

import staticdhcpdlib

setup(
 name = 'staticDHCPd',
 version = staticdhcpdlib.VERSION,
 description = "Highly customisable, static-lease-focused DHCP server",
 author = re.search(', (.*?) <', staticdhcpdlib.COPYRIGHT).group(1),
 author_email = re.search('<(.*?)>', staticdhcpdlib.COPYRIGHT).group(1),
 license = 'GPLv3',
 url = staticdhcpdlib.URL,
 packages = [
  'staticdhcpdlib',
  'staticdhcpdlib.databases',
  'staticdhcpdlib.web',
 ],
 data_files = [
  ('/etc/staticDHCPd', [
   'conf/conf.py.sample',
  ]),
  ('/etc/staticDHCPd/extensions', [
   'conf/extensions/HOWTO',
  ]),
 ],
 scripts = [
  'staticDHCPd',
 ],
)

#Post-installation stuff
if os.getenv('DEBUILD_MODE') != 'yes': #Don't print confusing stuff when building Debian packages
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
    "\tCopy control-scripts/staticDHCPd to /etc/init.d/staticDHCPd",
    "\tRun '/usr/sbin/update-rc.d staticDHCPd defaults'",
        ])
    elif platform.mac_ver()[0]:
        instructions.extend([
    "OS X",
    "\tCopy control-scripts/ca.uguu.puukusoft.staticDHCPd.plist to /Library/LaunchDaemons/"
        ])
    else:
        instructions.extend([
    "Instructions relevant to your platform are unavailable; please contribute documentation",
        ])

    for i in instructions:
        print(i)
        