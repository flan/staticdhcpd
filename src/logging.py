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

_LOG_LOCK = threading.Lock() #: A lock used to synchronize access to the memory-log.
_LOG = [] #: The memory-log.

_POLL_RECORDS_LOCK = threading.Lock() #: A lock used to synchronize access to the stats-log.
_POLL_RECORDS = [] #: The stats-log.

_EMAIL_LOCK = threading.Lock() #: A lock used to synchronize access to the e-mail routines.
_EMAIL_TIMEOUT = 0 #: The number of seconds left before another e-mail can be sent.

#Status-recording functions
def writeLog(data):
	"""
	Adds an entry to the memory-log.
	
	@type data: basestring
	@param data: The event to be logged.
	"""
	global _LOG
	
	_LOG_LOCK.acquire()
	try:
		_LOG = [(time.time(), data)] + _LOG[:conf.LOG_CAPACITY - 1]
		if conf.DEBUG:
			print '%(time)s : %(event)s' % {
			 'time': time.asctime(),
			 'event': data,
			}
	finally:
		_LOG_LOCK.release()
		
def readLog():
	"""
	Returns a static, immutable copy of the memory-log.
	
	@rtype: tuple
	@return: A collection of
		(timestamp:float, details:basestring) values, in reverse-chronological
		order.
	"""
	_LOG_LOCK.acquire()
	try:
		return tuple(_LOG)
	finally:
		_LOG_LOCK.release()
		
def writePollRecord(packets, discarded, time_taken, ignored_macs):
	"""
	Adds statistics to the stats-log.
	
	@type packets: int
	@param packets: The number of packets processed.
	@type discarded: int
	@param discarded: The number of processed packets that were discarded before
		being fully processed.
	@type time_taken: float
	@param time_taken: The number of seconds spent handling all received,
		non-ignored requests.
	@type ignored_macs: int
	@param ignored_macs: The number of MAC addresses being actively ignored.
	"""
	global _POLL_RECORDS
	
	_POLL_RECORDS_LOCK.acquire()
	try:
		_POLL_RECORDS = [(time.time(), packets, discarded, time_taken, ignored_macs)] + _POLL_RECORDS[:conf.POLL_INTERVALS_TO_TRACK - 1]
	finally:
		_POLL_RECORDS_LOCK.release()
		
def readPollRecords():
	"""
	Returns a static, immutable copy of the stats-log.
	
	@rtype: tuple
	@return: A collection of
		(timestamp:float, processed:int, discarded:int,
		processing_time:float, ignored_macs:int) values, in reverse-chronological
		order.
	"""
	_POLL_RECORDS_LOCK.acquire()
	try:
		return tuple(_POLL_RECORDS)
	finally:
		_POLL_RECORDS_LOCK.release()
		
#Logging functions
def logToDisk():
	"""
	Writes the current memory-log and stats-log to disk, making it possible to
	export information for use by a developer or to track a misbehaving client.
	
	If logging fails, a message will be written to the memory-log.
	
	@rtype: bool
	@return: True if the logfile was written.
	"""
	try:
		log_file = open(conf.LOG_FILE, 'w')
		
		log_file.write("Summary generated %(time)s\n" % {'time': time.asctime(),})
		
		log_file.write("\nStatistics:\n")
		for (timestamp, packets, discarded, time_taken, ignored_macs) in readPollRecords():
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
		for (timestamp, line) in readLog():
			log_file.write("%(time)s : %(line)s\n" % {
			 'time': time.ctime(timestamp),
			 'line': line,
			})
			
		log_file.close()
		
		return True
	except Exception, e:
		writeLog('Writing to disk failed: %(error)s' % {'error': str(e),})
		return False
		
#E-mail functions
def emailTimeoutCooldown():
	"""
	Ticks the e-mail timeout value, possibly allowing another e-mail to be sent.
	"""
	global _EMAIL_TIMEOUT
	
	_EMAIL_LOCK.acquire()
	_EMAIL_TIMEOUT = max(0, _EMAIL_TIMEOUT - conf.POLLING_INTERVAL)
	_EMAIL_LOCK.release()
	
def sendErrorReport(summary, exception):
	"""
	Sends e-mail using the config options specified, if e-mail is enabled.
	
	Since it's highly likely that any error that needs to be reported will fire
	for most, if not all, DHCP requests received, a cooldown is imposed to avoid
	flooding the recipient's inbox too quickly.
	
	If this function is unable to send e-mail, a summary of the error being
	reported will be written to the memory-log.
	
	@type summary: basestring
	@param summary: A short description of the error, including a probable
		cause, if known.
	@type exception: Exception
	@param exception: The C{Exception} raised to result in this message being
		sent.
	"""
	report ="""
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
	}
	
	if conf.DEBUG:
		print report
		
	if not conf.EMAIL_ENABLED:
		return
		
	global _EMAIL_TIMEOUT
	_EMAIL_LOCK.acquire()
	try:
		if _EMAIL_TIMEOUT > 0:
			return
		_EMAIL_TIMEOUT = conf.EMAIL_TIMEOUT
	finally:
		_EMAIL_LOCK.release()
		
	message = email.MIMEMultipart.MIMEMultipart()
	message['From'] = conf.EMAIL_SOURCE
	message['To'] = conf.EMAIL_DESTINATION
	message['Date'] = email.Utils.formatdate(localtime=True)
	message['Subject'] = 'Problem with the DHCP server'
	
	message.attach(email.MIMEText.MIMEText(report))
	
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
		