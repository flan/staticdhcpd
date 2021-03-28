#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
"""
Deployment script for libpydhcpserver.
"""
from distutils.core import setup
import re

import libpydhcpserver

setup(
 name='libpydhcpserver',
 version=libpydhcpserver.VERSION,
 description='Pure-Python, spec-compliant DHCP-packet-processing and networking library',
 long_description=(
  'libpydhcpserver provides the implementation for staticDHCPd\'s DHCP-processing'
  ' needs, but has a stable API and may be used by other applications that have a'
  ' reason to work with DHCP packets and perform server-oriented functions.'
 ),
 author=re.search(', (.*?) <', libpydhcpserver.COPYRIGHT).group(1),
 author_email=re.search('<(.*?)>', libpydhcpserver.COPYRIGHT).group(1),
 license='GPLv3',
 url=libpydhcpserver.URL,
 packages=[
  'libpydhcpserver',
  'libpydhcpserver.dhcp_types',
 ],
)
