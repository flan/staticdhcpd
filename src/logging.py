# -*- encoding: utf-8 -*-
"""
staticDHCPd module: src.logging

Purpose
=======
 Provides a means of logging information for a staticDHCPd server.
 
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
import email
import smtplib
import traceback
import threading
import time

import conf

_LOG_LOCK = threading.Lock()
_LOG = []

_POLL_RECORDS_LOCK = threading.Lock()
_POLL_RECORDS = []

def writeLog(data):
	global _LOG
	
	_LOG_LOCK.acquire()
	try:
		_LOG = [(time.time(), data)] + _LOG[:conf.LOG_CAPACITY - 1]
	finally:
		_LOG_LOCK.release()
		
def readLog():
	_LOG_LOCK.acquire()
	try:
		return tuple(_LOG)
	finally:
		_LOG_LOCK.release()
		
def writePollRecord(packets, discarded, time_taken, ignored_macs):
	global _POLL_RECORDS
	
	_POLL_RECORDS_LOCK.acquire()
	try:
		_POLL_RECORDS = [(time.time(), packets, discarded, time_taken, ignored_macs)] + _POLL_RECORDS[:conf.POLL_INTERVALS_TO_TRACK - 1]
	finally:
		_POLL_RECORDS_LOCK.release()
		
def readPollRecords():
	_POLL_RECORDS_LOCK.acquire()
	try:
		return tuple(_POLL_RECORDS)
	finally:
		_POLL_RECORDS_LOCK.release()
		
def logToDisk():
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
		
def sendErrorReport(summary, exception):
	if not conf.EMAIL_ENABLED:
		return
		
	message = email.MIMEMultipart.MIMEMultipart()
	message['From'] = conf.EMAIL_SOURCE
	message['To'] = conf.EMAIL_DESTINATION
	message['Date'] = email.Utils.formatdate(localtime=True)
	message['Subject'] = 'Problem with the DHCP server'
	
	message.attach(email.MIMEText.MIMEText(
"""
A problem occurred with the DHCP server running on %(server)s.

Given description:
	%(summary)s

Exception type:
	%(type)s

Exception details:
	%(details)s

Exception traceback:
%(traceback)s
""" % {
	 'server': conf.DHCP_SERVER_IP,
	 'summary': summary,
	 'type': str(type(exception)),
	 'details': str(exception),
	 'traceback': traceback.format_exc(),
	}))
	
	try:
		smtp_server = smtplib.SMTP(conf.EMAIL_SERVER)
		smtp_server.login(conf.EMAIL_USER, conf.EMAIL_PASSWORD)
		smtp_server.sendmail(
		 conf.EMAIL_SOURCE,
		 (conf.EMAIL_DESTINATION,),
		 message.as_string()
		)
		smtp_server.close()
		
		writeLog("E-mail about '%(error)s' sent to %(destination)s" % {
		 'error': exception,
		 'destination': conf.EMAIL_DESTINATION,
		})
	except Exception, e:
		writeLog("Unable to send e-mail about '%(e)s': %(error)s" % {
		 'e': e,
		 'error': exception,
		})
		