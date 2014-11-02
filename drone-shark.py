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
import struct
import socket
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

def parseData(host, port, pkt):
	if port['protocol'] == 'tcp':
		pass
	elif port['protocol'] == 'udp':
		pass
	elif port['protocol'] == 'icmp':
		pass

	return host, port

def parse():
	for packet in startCapture(interface='eth0', timeout=60):
		hostSrc = copy.deepcopy(models.host_model)
		hostDst = copy.deepcopy(models.host_model)
		hostSrc['alive'] = True
		hostDst['alive'] = True
		
		portSrc = copy.deepcopy(models.port_model)
		portDst = copy.deepcopy(models.port_model)
		
		hostSrc['mac_addr'] = packet[0].src
		hostDst['mac_addr'] = packet[0].dst
			
		if packet[1]._layer_name in ['ip', 'ipv6']:		
			hostSrc['string_addr'] = packet[1].src_host
			hostDst['string_addr'] = packet[1].dst_host
			if packet[1]._layer_name == 'ip':
				hostSrc['long_addr'] = struct.unpack("!L", socket.inet_aton(hostSrc['string_addr']))[0]
				hostDst['long_addr'] = struct.unpack("!L", socket.inet_aton(hostDst['string_addr']))[0]
			portSrc['protocol'] = packet[2]._layer_name
			portDst['protocol'] = packet[2]._layer_name
			portSrc['port'] = int(packet[2].srcport)
			portDst['port'] = int(packet[2].dstport)
			portSrc['alive'] = True
			portDst['alive'] = True
			portSrc['service'] = socket.getservbyport(portSrc['port'])
			portDst['service'] = socket.getservbyport(portDst['port'])
			
			try:
				data = packet[3]
			except:
				data = None
			
			(hostSrc, portSrc) = parseData(hostSrc, portSrc, packet)
			(hostDst, portDst) = parseData(hostDst, portDst, packet)
		elif packet[1]._layer_name == 'arp':
			hostSrc['string_addr'] = packet[1].src_proto_ipv4
			hostDst['string_addr'] = packet[1].dst_proto_ipv4
			hostSrc['long_addr'] = struct.unpack("!L", socket.inet_aton(hostSrc['string_addr']))[0]
			hostDst['long_addr'] = struct.unpack("!L", socket.inet_aton(hostDst['string_addr']))[0]
		else:
			'''Don't know what packet it is'''
			print packet[1]._layer_name
			continue
		
		hostSrc['ports'].append(portSrc)
		hostDst['ports'].append(portDst)
		project['hosts'].append(hostSrc)
		project['hosts'].append(hostDst)


if __name__ == '__main__':
	project = copy.deepcopy(models.project_model)
	project['project_id'] = 'test'  #need to get this to pull from somewhere
	command = copy.deepcopy(models.command_model)
	command['tool'] = TOOL
	parse()
