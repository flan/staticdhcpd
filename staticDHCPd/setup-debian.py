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
  ('/etc/staticDHCPd/extensions', [
   'conf/extensions/HOWTO',
  ]),
 ],
 scripts = [
  'staticDHCPd',
 ],
)
