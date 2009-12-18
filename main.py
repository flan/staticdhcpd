# -*- encoding: utf-8 -*-
"""
staticDHCPd module: main

Purpose
=======
 Runs a staticDHCPd server.
 
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
 
 (C) Neil Tallim, 2009
"""
import os
import signal
import sys
import time

import conf

import src.dhcp
import src.logging
import src.web

if not conf.DEBUG:
	sys.stdout = open('/dev/null', 'w')
	
def _quitHandler(signum, frame):
	"""
	Cleanly shuts down this daemon upon receipt of a SIGTERM.
	
	@type signum: int
	@param signum: The kill-signal constant received. This will always be
		SIGTERM.
	@type frame: int
	@param frame: The stack-frame in which the kill-signal was received.
		This is not used.
	"""
	#Remove PID.
	try:
		os.unlink(conf.PID_FILE)
	except:
		pass
		
	src.logging.logToDisk()
	
	exit(0)
	
def _reloadHandler(signum, frame):
	"""
	Reloads conf upon receipt of a SIGHUP.
	
	@type signum: int
	@param signum: The kill-signal constant received. This will always be
		SIGHUP.
	@type frame: int
	@param frame: The stack-frame in which the kill-signal was received.
		This is not used.
	"""
	try:
		reload(conf)
		src.logging.writeLog("Reloaded configuration")
	except Exception, e:
		src.logging.writeLog("Error while reloading configuration: %(error)s" % {
		 'error': str(e),
		})
		
	if not src.logging.logToDisk():
		src.logging.writeLog("Unable to write logfile: %(file)s" % {'file': conf.LOG_FILE,})
		
if __name__ == '__main__':
	dhcp_thread = src.dhcp.DHCPService()
	dhcp_thread.start()
	
	if conf.WEB_ENABLED:
		web_thread = src.web.WebService()
		web_thread.start()
	
	#Record PID.
	try:
		open(conf.PID_FILE, 'w').write(str(os.getpid()) + '\n')
	except:
		src.logging.writeLog("Unable to write pidfile: %(file)s" % {'file': conf.PID_FILE,})
		
	signal.signal(signal.SIGHUP, _reloadHandler)
	signal.signal(signal.SIGTERM, _quitHandler)
	
	os.setregid(conf.GID, conf.GID)
	os.setreuid(conf.UID, conf.UID)
	
	tick = 0
	while True:
		time.sleep(1)
		
		tick += 1
		if tick >= conf.POLLING_INTERVAL:
			dhcp_thread.getStats()
			tick = 0
			