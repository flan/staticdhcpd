#!/usr/bin/env python
"""
Deployment script for libpydhcpserver.
"""
from distutils.core import setup
import re

import libpydhcpserver

setup(
 name = 'libpydhcpserver',
 version = libpydhcpserver.VERSION,
 description = "Pure-Python, spec-compliant DHCP-packet-processing and networking library",
 author = re.search(', (.*?) <', libpydhcpserver.COPYRIGHT).group(1),
 author_email = re.search('<(.*?)>', libpydhcpserver.COPYRIGHT).group(1),
 license = 'GPLv3',
 url = libpydhcpserver.URL,
 packages = [
  'libpydhcpserver',
  'libpydhcpserver.dhcp_types',
 ],
)
