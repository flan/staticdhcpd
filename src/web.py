import BaseHTTPServer
import cgi
import threading
import time

import conf

import src.logging

class WebServer(BaseHTTPServer.BaseHTTPRequestHandler):
	_allowed_pages = ('/', '/index.html')
	
	def doResponse(self):
		try:
			if not self.path in self._allowed_pages:
				self.send_response(404)
				return
				
			self.send_response(200)
			self.send_header('Content-type', 'text/html')
			self.send_header('Last-modified', time.strftime('%a, %d %b %Y %H:%M:%S %Z'))
			self.end_headers()
			
			self.wfile.write('<html><head><title>staticDHCPd log</title></head><body><div style="width: 950px; margin-left: auto; margin-right: auto; border: 1px solid black;">')
			
			self.wfile.write('<div>Statistics:<div style="text-size: 0.9em; margin-left: 20px;">')
			for (timestamp, packets, discarded, time_taken, ignored_macs) in src.logging.readPollRecords():
				if packets:
					turnaround = time_taken / packets
				else:
					turnaround = 0.0
				self.wfile.write("%(time)s : processed: %(processed)i; discarded: %(discarded)i; turnaround: %(turnaround)fs/pkt; ignored MACs: %(ignored)i<br/>" % {
				 'time': time.ctime(timestamp),
				 'processed': packets,
				 'discarded': discarded,
				 'turnaround': turnaround,
				 'ignored': ignored_macs,
				})
			self.wfile.write("</div></div><br/>")
			
			self.wfile.write('<div>Event log:<div style="text-size: 0.9em; margin-left: 20px;">')
			for (timestamp, line) in src.logging.readLog():
				self.wfile.write("%(time)s : %(line)s<br/>" % {
				 'time': time.ctime(timestamp),
				 'line': cgi.escape(line),
				})
			self.wfile.write("</div></div><br/>")
			
			self.wfile.write('<div style="text-align: center;"><small>Summary generated %(time)s</small>' % {
			 'time': time.asctime(),
			})
			self.wfile.write('<br/><form action="/" method="post"><div><input type="submit" value="Reload configuration"/></div></form></div>')
			
			self.wfile.write("</div></body></html>")
			
			return
		except:
			pass
			
	def do_GET(self):
		self.doResponse()
		
	def do_POST(self):
		try:
			reload(conf)
			src.logging.writeLog("Reloaded configuration")
		except Exception, e:
			src.logging.writeLog("Error while reloading configuration: %(error)s" % {
			 'error': str(e),
			})
		self.doResponse()
		
	def do_HEAD(self):
		if not self.path in self._allowed_pages:
				self.send_response(404)
				return
				
		try:
			self.send_response(200)
			self.send_header('Content-type', 'text/html')
			self.send_header('Last-modified', time.strftime('%a, %d %b %Y %H:%M:%S %Z'))
			self.end_headers()
		except:
			pass
			
class WebService(threading.Thread):
	_web_server = None
	
	def __init__(self):
		threading.Thread.__init__(self)
		self.daemon = True
		
		self._web_server = BaseHTTPServer.HTTPServer(
		 (conf.WEB_IP, conf.WEB_PORT), WebServer
		)
		
		src.logging.writeLog('Configured Web server')
		
	def run(self):
		src.logging.writeLog('Running Web server')
		self._web_server.serve_forever()
		