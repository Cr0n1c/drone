#!/usr/bin/python
############################################################
##
##   Script: drone-multi
##   Developer: Brandon Helms
##   Summary: Used to import multiple files at once
##
############################################################
import os
from subprocess import check_output
from sys import exit, argv
from colorama import Fore
PROG_NAME = argv[0]
 
if __name__ == '__main__':
    if not len(argv) > 3:
        print 'Usage: %s <plugin_type> <project_id> <regex>' %PROG_NAME
        exit(1)
 
    pName = 'drone-' + argv[1].lower()
    pid = argv[2]
    files = argv[3:]
  
    #Checking to make sure we have the plugin
    try:
       check_output('which %s' %pName, shell=True)
    except:
        print Fore.RED + '[-] %s not a valid plugin type' % argv[1] + Fore.WHITE
        exit(1)
 
    #Running through files we found with our regex
    for f in files:
        if not f.endswith('.xml'):  #if file is not a xml, then f off
            print Fore.RED + '[-] File: %s --skipping' %f + Fore.WHITE
        else:
            print Fore.YELLOW + '[+] File: %s' %f + Fore.WHITE
            os.system('%s %s %s' %(pName, pid, f)) #was lazy, next version will use subprocess
