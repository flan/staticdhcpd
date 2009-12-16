# -*- encoding: utf-8 -*-
"""
staticDHCPd module: main

Purpose
=======
 Runs a staticDHCPd server.
 
Legal
=====
 All code, unless otherwise indicated, is original, and subject to the terms of
 the GNU General Public License version 3, which is provided in COPYING.
 
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

def _logStatus():
	try:
		log_file = open(conf.LOG_FILE, 'w')
		
		log_file.write("Summary generated %(time)s\n" % {'time': time.asctime(),})
		
		log_file.write("\nStatistics:\n")
		for (timestamp, packets, discarded, time_taken, ignored_macs) in src.logging.readPollRecords():
			if packets:
				turnaround = time_taken / packets
			else:
				turnaround = 0.0
			log_file.write("%(time)s : processed: %(processed)i; discarded: %(discarded)i; turnaround: %(turnaround)fs/pkt; ignored MACs: %(ignored)i\n" % {
			 'time': time.ctime(timestamp),
			 'processed': packets,
			 'discarded': discarded,
			 'turnaround': turnaround,
			 'ignored': ignored_macs,
			})
			
		log_file.write("\nEvents:\n")
		for (timestamp, line) in src.logging.readLog():
			log_file.write("%(time)s : %(line)s\n" % {
			 'time': time.ctime(timestamp),
			 'line': line,
			})
			
		log_file.close()
		
		return True
	except:
		return False
		
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
		
	_logStatus()
	
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
		
	if not _logStatus():
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
		if tick == conf.POLLING_INTERVAL:
			dhcp_thread.getStats()
			tick = 0
			