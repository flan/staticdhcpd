import BaseHTTPServer
import cgi
import threading
import time

import constants

class WebServer(BaseHTTPServer.BaseHTTPRequestHandler):
	def doResponse(self):
		try:
			self.send_response(200)
			self.send_header('Content-type', 'text/html')
			self.end_headers()
			
			self.wfile.write("<html><head><title>staticDHCPd log</title></head><body><div>")
			for (timestamp, line) in constants.readLog():
				self.wfile.write("%(time)s : %(line)s<br/>" % {
				 'time': time.ctime(timestamp),
				 'line': line,
				})
			self.wfile.write("</div>")
			self.wfile.write("<div>Timestamp: %(time)s</div>" % {
			 'time': time.asctime(),
			})
			self.wfile.write("</body></html>")
			
			return
		except:
			pass
			
	def do_GET(self):
		self.doResponse()
		
    def do_POST(self):
		self.doResponse()
		
class WebService(threading.Thread):
	_web_server = None
	
	def __init__(self, server_address, server_port):
		threading.Thread.__init__(self)
		self.daemon = True
		
		self._web_server = BaseHTTPServer.HTTPServer((server_address, server_port), WebServer)
		
		constants.writeLog('Configured Web server')
		
	def run(self):
		constants.writeLog('Running Web server')
		server.serve_forever()
		