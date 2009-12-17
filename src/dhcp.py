# -*- encoding: utf-8 -*-
"""
staticDHCPd module: src.dhcp

Purpose
=======
 Provides the DHCP side of a staticDHCPd server.
 
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
import sys
import threading
import time
import traceback

import conf

import src.logging
import sql

import pydhcplib.dhcp_network
import pydhcplib.dhcp_packet
import pydhcplib.type_hw_addr
import pydhcplib.type_strlist

def _sendErrorReport(summary, exception):
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
		
		src.logging.writeLog("E-mail about '%(error)s' sent to %(destination)s" % {
		 'error': exception,
		 'destination': conf.EMAIL_DESTINATION,
		})
	except Exception, e:
		src.logging.writeLog("Unable to send e-mail about '%(e)s': %(error)s" % {
		 'e': e,
		 'error': exception,
		})
		
def longToQuad(l):
	q = [l % 256]
	l /= 256
	q.insert(0, l % 256)
	l /= 256
	q.insert(0, l % 256)
	l /= 256
	q.insert(0, l % 256)
	return q
	
class DHCPServer(pydhcplib.dhcp_network.DhcpNetwork):
	_server_address = None
	_server_port = None
	_client_port = None
	
	_sql_broker = None
	
	_stats_lock = None
	_packets_processed = 0
	_packets_discarded = 0
	_time_taken = 0.0
	_dhcp_assignments = None
	_ignored_addresses = None
	
	def __init__(self, server_address, server_port, client_port):
		self._stats_lock = threading.Lock()
		self._dhcp_assignments = {}
		self._ignored_addresses = []
		
		self._server_address = server_address
		self._server_port = server_port
		self._client_port = client_port
		
		pydhcplib.dhcp_network.DhcpNetwork.__init__(
		 self, server_address, server_port, client_port
		)
		
		self.CreateSocket()
		self.BindToAddress()
		
		self._sql_broker = sql.SQL_BROKER()
		
	def evaluateRelay(self, packet):
		#If this is a relayed request, decide whether to handle it or not.
		giaddr = packet.GetGiaddr()
		if not giaddr == [0, 0, 0, 0]: #Relayed request.
			if not conf.ALLOW_DHCP_RELAYS: #Ignore it.
				return False
			elif conf.ALLOWED_DHCP_RELAYS and not '.'.join(map(str, giaddr)) in conf.ALLOWED_DHCP_RELAYS:
				src.logging.writeLog('Relayed request from unauthorized relay %(ip)s ignored' % {
				 'ip': '.'.join(map(str, giaddr)),
				})
				return False
		elif not conf.ALLOW_LOCAL_DHCP: #Local request, but denied.
			return False
		return True
		
	def HandleDhcpDiscover(self, packet):
		if not self.evaluateRelay(packet):
			return
			
		start_time = time.time()
		mac = pydhcplib.type_hw_addr.hwmac(packet.GetHardwareAddress())
		if not [None for (ignored_mac, timeout) in self._ignored_addresses if mac == ignored_mac]:
			self._logDHCPAccess(mac)
			
			src.logging.writeLog('DHCPDISCOVER received from %(mac)s' % {
			 'mac': mac,
			})
			
			try:
				result = self._sql_broker.lookupMAC(mac)
				if result:
					offer = pydhcplib.dhcp_packet.DhcpPacket()
					offer.CreateDhcpOfferPacketFrom(packet)
					
					offer.SetOption('server_identifier', [int(i) for i in self._server_address.split('.')])
					self._loadDHCPPacket(offer, result)
					if conf.loadDHCPPacket(offer, mac, [int(i) for i in result[0].split('.')], packet.GetGiaddr()):
						src.logging.writeLog('DHCPOFFER sent to %(mac)s' % {
						 'mac': mac,
						})
						self.SendDhcpPacket(offer)
					else:
						src.logging.writeLog('Ignoring %(mac)s per loadDHCPPacket()' % {
						 'mac': mac,
						})
						self._logDiscardedPacket()
				else:
					src.logging.writeLog('%(mac)s unknown; ignoring for %(time)i seconds' % {
					 'mac': mac,
					 'time': conf.UNAUTHORIZED_CLIENT_TIMEOUT,
					})
					self._stats_lock.acquire()
					self._ignored_addresses.append([mac, conf.UNAUTHORIZED_CLIENT_TIMEOUT])
					self._stats_lock.release()
			except Exception, e:
				_sendErrorReport('Unable to respond to %(mac)s' % {'mac': mac,}, e)
		else:
			self._logDiscardedPacket()
		self._logTimeTaken(time.time() - start_time)
		
	def HandleDhcpRequest(self, packet):
		if not self.evaluateRelay(packet):
			return
			
		start_time = time.time()
		mac = pydhcplib.type_hw_addr.hwmac(packet.GetHardwareAddress())
		if not [None for (ignored_mac, timeout) in self._ignored_addresses if mac == ignored_mac]:
			self._logDHCPAccess(mac)
			
			ip = packet.GetOption("request_ip_address")
			sid = packet.GetOption("server_identifier")
			ciaddr = packet.GetOption("ciaddr")
			s_ip = '.'.join(map(str, ip))
			s_sid = '.'.join(map(str, sid))
			s_ciaddr = '.'.join(map(str, ciaddr))
			
			if sid != [0,0,0,0] and ciaddr == [0,0,0,0]:
				#SELECTING
				src.logging.writeLog('DHCPREQUEST:SELECTING(%(ip)s) received from %(mac)s' % {
				 'ip': s_ip,
				 'mac': mac,
				})
				if s_sid == self._server_address: #Chosen!
					try:
						result = self._sql_broker.lookupMAC(mac)
						if not ip or (result and result[0] == s_ip):
							packet.TransformToDhcpAckPacket()
							self._loadDHCPPacket(packet, result)
							if conf.loadDHCPPacket(packet, mac, result[0], packet.GetGiaddr()):
								src.logging.writeLog('DHCPACK sent to %(mac)s' % {
								 'mac': mac,
								})
								self.SendDhcpPacket(packet)
							else:
								src.logging.writeLog('Ignoring %(mac)s per loadDHCPPacket()' % {
								 'mac': mac,
								})
								self._logDiscardedPacket()
						else:
							packet.TransformToDhcpNackPacket()
							src.logging.writeLog('DHCPNAK sent to %(mac)s' % {
							 'mac': mac,
							})
							self.SendDhcpPacket(packet)
					except Exception, e:
						_sendErrorReport('Unable to respond to %(mac)s' % {'mac': mac,}, e)
			elif sid == [0,0,0,0] and ciaddr == [0,0,0,0] and ip:
				#INIT-REBOOT
				src.logging.writeLog('DHCPREQUEST:INIT-REBOOT received from %(mac)s' % {
				 'mac': mac,
				})
				try:
					result = self._sql_broker.lookupMAC(mac)
					if result and result[0] == s_ip:
						packet.TransformToDhcpAckPacket()
						self._loadDHCPPacket(packet, result)
						if conf.loadDHCPPacket(packet, mac, ip, packet.GetGiaddr()):
							src.logging.writeLog('DHCPACK sent to %(mac)s' % {
							 'mac': mac,
							})
							self.SendDhcpPacket(packet)
						else:
							src.logging.writeLog('Ignoring %(mac)s per loadDHCPPacket()' % {
							 'mac': mac,
							})
							self._logDiscardedPacket()
					else:
						packet.TransformToDhcpNackPacket()
						src.logging.writeLog('DHCPNAK sent to %(mac)s' % {
						 'mac': mac,
						})
						self.SendDhcpPacket(packet)
				except Exception, e:
					_sendErrorReport('Unable to respond to %(mac)s' % {'mac': mac,}, e)
			elif sid == [0,0,0,0] and ciaddr != [0,0,0,0] and not ip:
				if conf.NAK_RENEWALS:
					packet.TransformToDhcpNackPacket()
					src.logging.writeLog('DHCPNAK sent to %(mac)s per NAK_RENEWALS setting' % {
					 'mac': mac,
					})
					self.SendDhcpPacket(packet, s_ciaddr)
				else:
					if packet.GetOption("ciaddr") == [255,255,255,255]:
						#REBINDING
						src.logging.writeLog('DHCPREQUEST:REBIND received from %(mac)s' % {
						 'mac': mac,
						})
						src.logging.writeLog('Requiring %(mac)s to initiate DISCOVER' % {
						 'mac': mac,
						})
					else:
						#RENEWING
						src.logging.writeLog('DHCPREQUEST:RENEW received from %(mac)s' % {
						 'mac': mac,
						})
						if conf.ALLOW_DHCP_RENEW:
							try:
								result = self._sql_broker.lookupMAC(mac)
								if result and result[0] == s_ciaddr:
									packet.TransformToDhcpAckPacket()
									packet.SetOption('yiaddr', ciaddr)
									self._loadDHCPPacket(packet, result)
									if conf.loadDHCPPacket(packet, mac, ciaddr, packet.GetGiaddr()):
										src.logging.writeLog('DHCPACK sent to %(mac)s' % {
										 'mac': mac,
										})
										self.SendDhcpPacket(packet, s_ciaddr)
									else:
										src.logging.writeLog('Ignoring %(mac)s per loadDHCPPacket()' % {
										 'mac': mac,
										})
										self._logDiscardedPacket()
								else:
									packet.TransformToDhcpNackPacket()
									src.logging.writeLog('DHCPNAK sent to %(mac)s' % {
									 'mac': mac,
									})
									self.SendDhcpPacket(packet, s_ciaddr)
							except Exception, e:
								_sendErrorReport('Unable to respond to %(mac)s' % {'mac': mac,}, e)
						else:
							src.logging.writeLog('Requiring %(mac)s to initiate DISCOVER' % {
							 'mac': mac,
							})
			else:
				src.logging.writeLog('DHCPREQUEST:UNKNOWN received from %(mac)s' % {
				 'mac': mac,
				})
				self._logDiscardedPackets()
		else:
			self._logDiscardedPacket()
		self._logTimeTaken(time.time() - start_time)
		
	def _loadDHCPPacket(self, packet, result):
		(ip, gateway, subnet_mask, broadcast_address, domain_name, domain_name_servers, lease_time) = result
		packet.SetOption('yiaddr', [int(i) for i in ip.split('.')])
		packet.SetOption('ip_address_lease_time', longToQuad(lease_time))
		
		#Default gateway, subnet mask, and broadcast address.
		if gateway:
			packet.SetOption('router', [int(i) for i in gateway.split('.')])
		if subnet_mask:
			packet.SetOption('subnet_mask', [int(i) for i in subnet_mask.split('.')])
		if broadcast_address:
			packet.SetOption('broadcast_address', [int(i) for i in broadcast_address.split('.')])
			
		#Search domain/nameservers.
		if domain_name:
			packet.SetOption('domain_name', pydhcplib.type_strlist.strlist(domain_name).list())
		if domain_name_servers:
			dns_list = []
			for dns in domain_name_servers.split(','):
				dns_list += [int(i) for i in dns.strip().split('.')]
			packet.SetOption('domain_name_server', dns_list)
			
	def SendDhcpPacket(self, packet, _ip=None):
		if _ip:
			bytes = self.SendDhcpPacketTo(packet, _ip)
			src.logging.writeLog('%(bytes)i-byte packet sent to client at %(ip)s' % {
			 'bytes': bytes,
			 'ip': _ip,
			})
			return bytes
		else:
			giaddr = packet.GetGiaddr()
			if giaddr == [0, 0, 0, 0]:
				bytes = self.SendDhcpPacketTo(packet, '255.255.255.255')
				src.logging.writeLog('%(bytes)i-byte packet sent to broadcast address' % {
				 'bytes': bytes,
				})
				return bytes
			else:
				giaddr = '.'.join(map(str, giaddr))
				bytes = self.SendDhcpPacketTo(packet, giaddr)
				src.logging.writeLog('%(bytes)i-byte packet sent to relay gateway %(giaddr)s' % {
				 'bytes': bytes,
				 'giaddr': giaddr,
				})
				return bytes
				
	def GetNextDhcpPacket(self):
		if pydhcplib.dhcp_network.DhcpNetwork.GetNextDhcpPacket(self):
			self._stats_lock.acquire()
			self._packets_processed += 1
			self._stats_lock.release()
			
	def _logTimeTaken(self, time_taken):
		self._stats_lock.acquire()
		self._time_taken += time_taken
		self._stats_lock.release()
		
	def _logDiscardedPacket(self):
		self._stats_lock.acquire()
		self._packets_discarded += 1
		self._stats_lock.release()
		
	def _logDHCPAccess(self, mac):
		self._stats_lock.acquire()
		assignments = self._dhcp_assignments.get(mac)
		if not assignments:
			self._dhcp_assignments[mac] = 1
		else:
			self._dhcp_assignments[mac] = assignments + 1
			if assignments + 1 > conf.SUSPEND_THRESHOLD:
				src.logging.writeLog('%(mac)s is issuing too many requests; ignoring for %(time)i seconds' % {
				 'mac': mac,
				 'time': conf.MISBEHAVING_CLIENT_TIMEOUT,
				})
				self._ignored_addresses.append([mac, conf.MISBEHAVING_CLIENT_TIMEOUT])
		self._stats_lock.release()
		
	def getStats(self):
		self._stats_lock.acquire()
		try:
			for i in range(len(self._ignored_addresses)):
				self._ignored_addresses[i][1] -= conf.POLLING_INTERVAL
			self._ignored_addresses = [address for address in self._ignored_addresses if address[1] > 0]
			
			stats = (self._packets_processed, self._packets_discarded, self._time_taken, len(self._ignored_addresses))
			
			self._dhcp_assignments = {}
			self._packets_processed = 0
			self._packets_discarded = 0
			self._time_taken = 0.0
			
			return stats
		finally:
			self._stats_lock.release()
			
class DHCPService(threading.Thread):
	_dhcp_server = None
	
	def __init__(self):
		threading.Thread.__init__(self)
		self.daemon = True
		
		self._dhcp_server = DHCPServer(
		 conf.DHCP_SERVER_IP,
		 conf.DHCP_SERVER_PORT,
		 conf.DHCP_CLIENT_PORT
		)
		
		src.logging.writeLog('Configured DHCP server')
		
	def run(self):
		src.logging.writeLog('Running DHCP server')
		while True:
			self._dhcp_server.GetNextDhcpPacket()
			
	def getStats(self):
		(processed, discarded, time_taken, ignored_macs) = self._dhcp_server.getStats()
		src.logging.writePollRecord(processed, discarded, time_taken, ignored_macs)
		
