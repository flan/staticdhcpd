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
 
 (C) Neil Tallim, 2009 <red.hamsterx@gmail.com>
"""
import os
import signal
import sys
import time

import src.conf_buffer as conf
import src.dhcp
import src.logging
import src.web

if not conf.DEBUG: #Suppress all unnecessary prints. 
    sys.stdout = sys.stderr = open('/dev/null', 'w')
else:
    sys.stdout = sys.stderr
    
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
    
def _logHandler(signum, frame):
    """
    Flushes DHCP cache and writes log to disk upon receipt of a SIGHUP.
    
    @type signum: int
    @param signum: The kill-signal constant received. This will always be
        SIGHUP.
    @type frame: int
    @param frame: The stack-frame in which the kill-signal was received.
        This is not used.
    """
    src.dhcp.flushCache()
    if not src.logging.logToDisk():
        src.logging.writeLog("Unable to write logfile: %(log)s" % {'log': conf.LOG_FILE,})
    else:
        src.logging.writeLog("Wrote log to '%(log)s'" % {'log': conf.LOG_FILE,})
        
def _daemonise():
	if os.fork(): #This is the parent
		sys.exit(0)
	os.setsid() #Ensure session semantics are configured
	os.chdir('/') #Avoid holding references to unstable resources
	
	#And lastly, clean up the base descriptors
	os.dup2(open('/dev/null', 'r').fileno(), sys.stdin.fileno())
	os.dup2(open('/dev/null', 'a+').fileno(), sys.stdout.fileno())
	os.dup2(open('/dev/null', 'a+', 0).fileno(), sys.stderr.fileno())
	
if __name__ == '__main__':
    #Ensure that pre-setup tasks are taken care of.
    conf.init()
	
	if conf.DAEMON:
		_daemonise()
		
    #Start Web server.
    if conf.WEB_ENABLED:
        web_thread = src.web.WebService()
        web_thread.start()
        
    #Start DHCP server.
    dhcp_thread = src.dhcp.DHCPService()
    dhcp_thread.start()
    
    #Record PID.
    try:
        pidfile = open(conf.PID_FILE, 'w')
        pidfile.write(str(os.getpid()) + '\n')
        pidfile.close()
        os.chown(conf.PID_FILE, conf.UID, conf.GID)
    except:
        src.logging.writeLog("Unable to write pidfile: %(file)s" % {'file': conf.PID_FILE,})
        
    #Touch logfile.
    try:
        open(conf.LOG_FILE, 'a').close()
        os.chown(conf.LOG_FILE, conf.UID, conf.GID)
    except:
        src.logging.writeLog("Unable to write pidfile: %(file)s" % {'file': conf.PID_FILE,})
        
    #Set signal-handlers.
    signal.signal(signal.SIGHUP, _logHandler)
    signal.signal(signal.SIGTERM, _quitHandler)
    
    #Set proper permissions for execution
    os.setregid(conf.GID, conf.GID)
    os.setreuid(conf.UID, conf.UID)
    
    #Serve until interrupted.
    tick = 0
    while True:
        time.sleep(1)
        
        tick += 1
        if tick >= conf.POLLING_INTERVAL: #Perform periodic cleanup.
            dhcp_thread.pollStats()
            src.logging.emailTimeoutCooldown()
            tick = 0
            
