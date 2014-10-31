#!/usr/bin/python
######################################################################################
##
##    Program: drone-shark
##    Version: 0.1
##    Developer: Brandon Helms
##    Notes:  Requires pyShark, but if not installed will install it for you.  This
##       will pull a running capture and parse the data and ship to LAIR as needed.
##
######################################################################################

import sys
import copy
from lairdrone import drone_models as models
from lairdrone import helper

OS_WEIGHT = 100
TOOL = 'tshark'

#Downloading dependencies and making sure pyShark is installed.
try:
	import pyshark
except ImportError:
	try:
		import pip
	except ImportError:
		import urllib
		import subprocess
		import os

		urllib.urlretrieve('https://bootstrap.pypa.io/get-pip.py', 'get-pip.py')
		subprocess.check_output('python ./get-pip.py', shell=True)
		os.remove('./get-pip.py')
	finally:
		subprocess.check_output('pip install pyshark', shell=True)
		import pyshark


def startCapture(interface='eth0', timeout=60):
	cap = pyshark.LiveCapture(interface)
	cap.sniff(timeout)
	return cap

def dissectPackets(listOfPackets):
	for packet in listOfPackets:
		host_dict = copy.deepcopy(models.host_model)
		host_dict['alive'] = True
		port_dict = copy.deepcopy(models.port_model)
		
		if not packet[1]._layer_name == 'ip':
		    continue	
		
		try:
			data = packet[3]
		except:
			data = None
		
		if packet[1].proto == 6:
			port_dict['protocol'] = 'tcp'
		elif packet[1].proto == 17:
			port_dict['protocol'] = 'udp'
		elif packet[1].proto == 13:
			port_dict['protocol'] = 'icmp'
		
		port_dict['port'] = int(packet[2].srcport)
		port_dict['alive'] = True
		host_dict['string_addr'] = packet[1].src_host
		host_dict['mac_addr'] = packet[0].src
		host_dict['ports'].append(port_dict)
		project_dict['hosts'].append(host_dict)
		


if __name__ == '__main__':
	project_dict = copy.deepcopy(models.project_model)
	project_dict['project_id'] = 'test'  #need to get this to pull from somewhere
	command_dict = copy.deepcopy(models.command_model)
	command_dict['tool'] = TOOL
	
	cap = startCapture()
	dissectPackets(cap)
	pprint.pprint(project_dict)
