#!/usr/bin/python
######################################################################################
##
##    Program: drone-shark
##    Version: 0.0.1
##    Developer: Brandon Helms
##    Notes:  Requires pyShark, but if not installed will install it for you.  This
##       will pull a running capture and parse the data and ship to LAIR as needed.
##
######################################################################################

import sys
import os
import struct
import socket
import copy

from optparse import OptionParser
from lairdrone import api, drone_models as models
from lairdrone import helper

OS_WEIGHT = 50
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
        
        urllib.urlretrieve('https://bootstrap.pypa.io/get-pip.py', 'get-pip.py')
        subprocess.check_output('python ./get-pip.py', shell=True)
        os.remove('./get-pip.py')
    finally:
        subprocess.check_output('pip install pyshark', shell=True)
        import pyshark


def startCapture(interface='eth0', timeout=60, filter=''):
    ''' Setup and starts capture based on interface, timeout and bpf_filter'''
    cap = pyshark.LiveCapture(interface)
    cap.bpf_filter = filter
    cap.sniff(timeout)
    return cap


def parseData(host, port, pkt):
    ''' This is basically my filter function to pull out data I care about'''
    if port['protocol'] == 'tcp':
        if 'http' in dir(pkt):
            port['service'] = 'http'
            if host['string_addr'] == pkt.ip.addr:
                if 'host' in dir(pkt.http):
                    host['hostnames'].append(pkt.http.host)
            else:
                if 'user_agent' in dir(pkt.http):   
                    host['os'].append(pkt.http.user_agent)   
                if 'server' in dir(pkt.http):
                    host['os'].append(pkt.http.server) 
    elif port['protocol'] == 'udp':
        if 'smb' in dir(pkt) and 'browser' in dir(pkt):
            if host['string_addr'] == pkt.nbdgm.src_ip:
                host['os'].append(pkt.browser.os_major + '.' + pkt.browser.os_minor) 
                host['hostnames'].append(pkt.browser.server)
                port['notes'].append(str(pkt.browser))
                port['notes'].append(pkt.browser.comment)
        elif 'snmp' in dir(pkt):
            if pkt.udp.port == port['port'] and host['string_addr'] == pkt.ip.addr:
                port['credentials'].append(pkt.snmp.community)
                port['notes'].append(str(pkt.snmp))
    elif port['protocol'] == 'icmp':
        pass
    
    return host, port


def parse():
    ''' This is my main function '''
    hostList = []
    
    for packet in capture:
        hostSrc = copy.deepcopy(models.host_model)
        hostSrc['alive'] = True
        hostSrc['last_modified_by'] = TOOL
        hostDst = copy.deepcopy(models.host_model)
        hostDst['alive'] = True
        hostDst['last_modified_by'] = TOOL
        
        portSrc = copy.deepcopy(models.port_model)
        portSrc['last_modified_by'] = TOOL
        portSrc['alive'] = True
        portDst = copy.deepcopy(models.port_model)
        portDst['last_modified_by'] = TOOL
        portDst['alive'] = True
        
        hostSrc['mac_addr'] = packet[0].src
        hostDst['mac_addr'] = packet[0].dst
        
        if packet[1]._layer_name in ['ip', 'ipv6']:        
            hostSrc['string_addr'] = packet[1].src_host
            hostDst['string_addr'] = packet[1].dst_host
            if packet[1]._layer_name == 'ip':
                hostSrc['long_addr'] = struct.unpack("!L", socket.inet_aton(hostSrc['string_addr']))[0]
                hostDst['long_addr'] = struct.unpack("!L", socket.inet_aton(hostDst['string_addr']))[0]
            
            for foundHost in hostList:
                if foundHost['string_addr'] == hostSrc['string_addr']:
                    hostSrc = foundHost
                    hostList.remove(foundHost)
                    break
            
            portSrc['protocol'] = packet[2]._layer_name
            portDst['protocol'] = packet[2]._layer_name
            portSrc['port'] = int(packet[2].srcport)
            portDst['port'] = int(packet[2].dstport)
            
            try:
                portSrc['service'] = socket.getservbyport(portSrc['port'])
            except socket.error:
                pass
            
            try:
                portDst['service'] = socket.getservbyport(portDst['port'])
            except socket.error:
                pass
            
            (hostSrc, portSrc) = parseData(hostSrc, portSrc, packet)
            (hostDst, portDst) = parseData(hostDst, portDst, packet)
        elif packet[1]._layer_name == 'arp':
            hostSrc['string_addr'] = packet[1].src_proto_ipv4
            hostDst['string_addr'] = packet[1].dst_proto_ipv4
            hostSrc['long_addr'] = struct.unpack("!L", socket.inet_aton(hostSrc['string_addr']))[0]
            hostDst['long_addr'] = struct.unpack("!L", socket.inet_aton(hostDst['string_addr']))[0]
            
            for foundHost in hostList:
                if foundHost['string_addr'] == hostSrc['string_addr']:
                    hostSrc = foundHost
                    hostList.remove(foundHost)
                    break
        else:
            '''Don't know what packet it is'''
            print packet[1]._layer_name
            continue
        
        hostSrc['ports'].append(portSrc)
        hostDst['ports'].append(portDst)
        '''
        project['hosts'].append(hostSrc)
        project['hosts'].append(hostDst)
        '''
        hostList.append(hostSrc)
        hostList.append(hostDst)
    
    for host in hostList:
        project['hosts'].append(host)
       

if __name__ == '__main__':
    '''
    usage = "usage: %prog <project_id> <bpf_filter> <timeout_in_secs>"
    description = "%prog runs tshark and ports data into Lair"
    
    parser = OptionParser(usage=usage, description=description,
                          version="%prog 0.0.1")

    parser.add_option(
        "--include-informational",
        dest="include_informational",
        default=False,
        action="store_true",
        help="Forces informational plugins to be loaded"
    )

    (options, args) = parser.parse_args()
    if len(args) != 3:
        print parser.get_usage()
        sys.exit(1)
    ''' 
    args = ['test', 'tcp port 80', 60]
    capture = startCapture(interface='eth0', timeout=int(args[2]), filter=args[1])
    project = copy.deepcopy(models.project_model)
    project['project_id'] = args[0]
    
    command = copy.deepcopy(models.command_model)
    command['tool'] = TOOL
    command['command'] = TOOL
    for arg in capture.get_parameters():
        if ' ' in arg:
            command['command'] += ' "%s"' %arg
        else:
            command['command'] += ' %s' %arg
        
    parse()
    
    # Import data into LAIR
    #db = api.db_connect()
    parse()
    #api.save(project, db, TOOL)
    #sys.exit(0)

