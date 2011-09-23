# Copyright (c) 2011 Patryk Orwat
# http://www.opensource.org/licenses/mit-license.php

import struct,string
import hashlib
import sys, os, cPickle
import ConfigParser

from twisted.application import service, internet
from twisted.internet import protocol, reactor

# from https://github.com/von/pyPerspectives
import Perspectives

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
		self.data = set()
		if os.path.isfile(dbname):
			f = open(dbname, 'r')
			for line in f:
				l = line.rstrip()
				self.data.add(l)
			f.close()
			print 'LOADED',len(self.data),'SHA-256 HASHES'

	def checkPerspectives(self, host, port, ask_md5_hash):
		notaries = Perspectives.Notaries.from_file("config/perspectives_notary_list.txt")
		s = Perspectives.Service(host, port)
		responses = notaries.query(s)
		answers={}
		ans_no=0
		for response in responses:
			if response is not None:
				ans_no+=1
				md5_hash = string.replace(str(response.last_key_seen().fingerprint),':','')
				if answers.has_key(md5_hash):
					answers[md5_hash]+=1
				else:
					answers[md5_hash]=1
		if answers.has_key(ask_md5_hash) and ans_no != 0 and answers[ask_md5_hash] >= ans_no/2:	# at least half of the answers must have the same hash !
			return True
		else:
			return False
		
	def check(self, sha1):
		if sha1 in self.data:
			return True
		else:
			return False

	def add(self, sha1):
		self.data.add(sha1)

	def stopService(self):
		service.Service.stopService(self)
		f = open(self.dbname, 'w')
		for h in self.data:
			f.write(h+'\n')
		f.close()

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
				self.cert_sha256 = hashlib.sha256(data[5*iter_no+shift+15:5*iter_no+shift+15+cert_size]).hexdigest()
				self.cert_md5 = hashlib.md5(data[5*iter_no+shift+15:5*iter_no+shift+15+cert_size]).hexdigest()

				if perspectives_on == 1:
					if not checker.checkPerspectives(self.host,self.port, self.cert_md5):
						print 'PERSPECTIVES DENIED CERT (MD5 HASH: %s)' % (self.cert_md5)
						self.transport.loseConnection()
				else:
					if not checker.check(self.cert_sha256) and allowmode == 0:
						print 'CERTIFICATE (SHA-256 HASH: %s) FOR SITE %s WASN\'T FOUND' % (self.cert_sha256, self.host)
						self.server.transport.loseConnection()
						self.transport.loseConnection()
					if allowmode == 1:
						checker.add(self.cert_sha256)
						print 'CERTIFICATE (SHA-256 HASH: %s) FOR SITE %s WAS ADDED' % (self.cert_sha256, self.host)
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
allowmode = int(parser.get('config','allowmode'))
datafile = parser.get('config','datafile')
perspectives_on = int(parser.get('config','perspectives'))

application = service.Application('Shikai')
shikai_service = service.IServiceCollection(application)

checker = Checker(datafile)
checker.setName('Checker')
checker.setServiceParent(shikai_service)

shikaifactory = protocol.Factory()
shikaifactory.protocol = Shikai
internet.TCPServer(listenport, shikaifactory).setServiceParent(shikai_service)
