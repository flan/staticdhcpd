#!/usr/bin/env python
"""
Deployment script for libpydhcpserver.
"""
from distutils.core import setup

from libpydhcpserver import VERSION

setup(
 name = 'libpydhcpserver',
 version = VERSION,
 description = "A well-tested, spec-compliant DHCP-packet-processing library",
 author = 'Neil Tallim',
 author_email = 'flan@uguu.ca',
 license = 'GPLv3',
 url = 'http://staticdhcpd.googlecode.com/',
 packages = [
  'libpydhcpserver',
  'libpydhcpserver.dhcp_types',
 ],
)
