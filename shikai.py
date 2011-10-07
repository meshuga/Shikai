# Copyright (c) 2011 Patryk Orwat
# http://www.opensource.org/licenses/mit-license.php

import struct, socket, string
import hashlib
import os, sqlite3
import ConfigParser

from OpenSSL import SSL
from StringIO import StringIO
import json

from twisted.application import service, internet
from twisted.internet import protocol, reactor

# from https://github.com/von/pyPerspectives
import Perspectives

def verify_cb(conn, cert, errnum, depth, ok):
	if checker.checkConvergenceNotaryHash(cert.digest('sha1')):
		return True
	else:
		return False

class RemoteConnectionFactory(protocol.ClientFactory):
	def __init__(self, client):
		self.client = client

	def buildProtocol(self, addr):
		return self.protocol(self.client)


class RemoteConnection(protocol.Protocol):
	def __init__(self, client):
		self.client = client
		self.client.server = self
		self.serverHello = ""

	def connectionLost(self, reason):
		try:
			self.client.transport.loseConnection()
		except:
			pass
        
	def dataReceived(self, data):
		if not self.client.finished:
			if self.client.side != 2: # ping...
				self.client.side = 2
				self.client.number += 1			
			if self.client.number == 2: # Server side handshake with certificate - if no break connection!!
				self.serverHello += data
		self.client.transport.write(data)

	def connectionMade(self):
		self.client.connectCompleted()

class Checker(service.Service):
	def __init__(self, dbname):
		self.dbname = dbname

		if not os.path.isfile(dbname):	# The database file doesn't exist
			self.connection = sqlite3.connect(dbname)
			self.cursor = self.connection.cursor()
			self.cursor.execute("CREATE TABLE fingerprints (id INTEGER PRIMARY KEY, host TEXT, sha1 TEXT)")
			self.connection.commit()
		else:
			self.connection = sqlite3.connect(dbname)
			self.cursor = self.connection.cursor()

		self.loadConvergenceNotaries()

	def loadConvergenceNotaries(self):
		f = open('config/convergence_notary_list.txt','r')
		self.convergenceNotaries = []
		for line in f:
			l = line.split(' ')
			l[1] = l[1].rstrip()
			self.convergenceNotaries.append(l)

	def checkConvergenceNotaryHash(self, notary_SHA1):
		for notary in self.convergenceNotaries:
			if string.replace(notary_SHA1,':','') == notary[1]:
				return True
		return False

	def checkConvergenceNotary(self, host, port, host_to_ask, port_to_ask, ask_sha1_hash):
		ctx = SSL.Context(SSL.SSLv3_METHOD)
		ctx.set_verify(SSL.VERIFY_PEER, verify_cb)

		sock = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))

		postData = 'fingerprint='+ask_sha1_hash
		data = 'POST /target/' + host_to_ask + '+' + str(port_to_ask) + ' HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\nContent-Length: '+str(len(postData))+'\r\n\r\n' + postData
		sock.connect((host, port))
		answer = ''
		try:
			sock.send(data)
			while True:
				recv = sock.recv(4096)
				if not recv: break
				answer += recv
		except SSL.Error:
			pass
		is_listed = False
		if answer:
			index = answer.find('\r\n\r\n')
			json_ans_str = answer[index+4:]
			json_ans = json.load(StringIO(json_ans_str))
			for fingerprint in json_ans[u'fingerprintList']:
				if string.replace(fingerprint[u'fingerprint'].encode('ascii','ignore'),':','') == ask_sha1_hash.upper():
					is_listed = True
					break
		return is_listed

	def checkConvergence(self, host_to_ask, port_to_ask, ask_sha1_hash):
		for notary in self.convergenceNotaries:
			if not self.checkConvergenceNotary(notary[0], 443, host_to_ask, port_to_ask, ask_sha1_hash):
				return False
		return True

	def checkPerspectives(self, host, port, ask_md5_hash):
		notaries = Perspectives.Notaries.from_file("config/perspectives_notary_list.txt")
		s = Perspectives.Service(host, port)
		responses = notaries.query(s)
		answers = {}
		ans_no = 0
		for response in responses:
			if response is not None:
				ans_no += 1
				md5_hash = string.replace(str(response.last_key_seen().fingerprint),':','')
				if answers.has_key(md5_hash):
					answers[md5_hash] += 1
				else:
					answers[md5_hash] = 1
		if answers.has_key(ask_md5_hash) and ans_no != 0 and answers[ask_md5_hash] >= ans_no/2:	# at least half of the answers must have the same hash !
			return True
		else:
			return False
		
	def check(self, host, sha1):
		self.cursor.execute('SELECT * FROM fingerprints WHERE host = ?', (host,))
		for ans in self.cursor:
			if ans[2].encode('ascii','ignore') == sha1:
				return True
		return False

	def add(self, host, sha1):
		self.cursor.execute('INSERT INTO fingerprints (host, sha1) VALUES (?, ?)', (host, sha1))
		self.connection.commit()

	def stopService(self):
		service.Service.stopService(self)
		self.connection.close()

class Shikai(protocol.Protocol):
	def __init__(self):
		self.server = None
		self.initialized = False
		self.finished = False

	def connectCompleted(self):
		self.transport.write('HTTP/1.0 200 Connection established\r\n\r\n')
		self.initialized = True
		self.number = 0
		self.side = -1
		self.transport.startReading()

	def handleHostResolvedSuccess(self, address):
		remote = RemoteConnectionFactory(self)
		remote.protocol = RemoteConnection
		internet.TCPClient(address, self.port, remote).setServiceParent(shikai_service)

	def handleHostResolvedError(self, error):
		print 'Error with DNS for:',self.host
		self.transport.loseConnection()

	def connect(self):
		self.transport.stopReading()
		deferred = reactor.resolve(self.host)
		deferred.addCallback(self.handleHostResolvedSuccess)
		deferred.addErrback(self.handleHostResolvedError)

	def processData(self):
		'''
		We assume that the communication is correct :) 
		Server should send the certigicate at the beginng of the communication.
		'''
		data = self.server.serverHello # server side handshake
		lenght = len(data) # overall lenght of server side handshake
		iter_no = 0
		shift = 0
		while 5*iter_no+shift+6 < lenght:	# There must be a certificate somewhere - if not, cert was sent earlier and we're not processing a handshake
			content_type, _, _, partlen, hand_type = struct.unpack('!BBBHB', data[5*iter_no+shift:5*iter_no+shift+6])
			if content_type != 22 and iter_no == 0:
				break	# it's not a handshake
			if hand_type == 11:	# It's a certificate - if there's a chain of certs, we only take care of the first cert
				(cert_size,) = struct.unpack('!H', data[5*iter_no+shift+13:5*iter_no+shift+15])	# It's a 3 byte field, but usually only 2 less significant are used
				self.cert_sha1 = hashlib.sha1(data[5*iter_no+shift+15:5*iter_no+shift+15+cert_size]).hexdigest()
				self.cert_md5 = hashlib.md5(data[5*iter_no+shift+15:5*iter_no+shift+15+cert_size]).hexdigest()

				if not checker.check(self.host, self.cert_sha1):
					if convergence_on == 1:
						if not checker.checkConvergence(self.host, self.port, self.cert_sha1):
							print 'CONVERGENCE DENIED CERT (SHA1 HASH: %s)  FOR SITE %s' % (self.cert_sha1, self.host)
							self.transport.loseConnection()
						else:
							checker.add(self.host, self.cert_sha1)
							print 'CERTIFICATE (SHA-1 HASH: %s) FOR SITE %s WAS ADDED' % (self.cert_sha1, self.host)
					if perspectives_on == 1:
						if not checker.checkPerspectives(self.host,self.port, self.cert_md5):
							print 'PERSPECTIVES DENIED CERT (MD5 HASH: %s) FOR SITE %s' % (self.cert_md5, self.host)
							self.transport.loseConnection()
						else:
							checker.add(self.host, self.cert_sha1)
							print 'CERTIFICATE (SHA-1 HASH: %s) FOR SITE %s WAS ADDED' % (self.cert_sha1, self.host)
					if convergence_on == 0 and perspectives_on == 0:
						self.transport.loseConnection() # Neither Convergence nor Perspectives is on
			iter_no+=1
			shift+=partlen		

	def dataReceived(self, data):
		if self.initialized is False:
			if data.splitlines()[0].split(' ')[0] != 'CONNECT':
				self.transport.write('HTTP/1.0 400 Bad Request\r\n\r\n')
				self.transport.loseConnection()
				return
			self.host = data.splitlines()[0].split(' ')[1].split(':')[0]
			self.port = int(data.splitlines()[0].split(' ')[1].split(':')[1])
			self.connect()

		else:
			if not self.finished:
				if self.side != 1: # ... pong
					self.side = 1
					self.number += 1
				if self.number == 3:
					self.finished = True
					self.processData()
			self.server.transport.write(data)

	def connectionLost(self, reason):
		try:
			if self.server:
				self.server.transport.loseConnection()
		except:
			pass

parser = ConfigParser.SafeConfigParser()
parser.read('config/shikai_config')
listenport = int(parser.get('config','port'))
datafile = parser.get('config','datafile')
perspectives_on = int(parser.get('config','perspectives'))
convergence_on = int(parser.get('config','convergence'))

application = service.Application('Shikai')
shikai_service = service.IServiceCollection(application)

checker = Checker(datafile)
checker
checker.setName('Checker')
checker.setServiceParent(shikai_service)

shikaifactory = protocol.Factory()
shikaifactory.protocol = Shikai
internet.TCPServer(listenport, shikaifactory).setServiceParent(shikai_service)
