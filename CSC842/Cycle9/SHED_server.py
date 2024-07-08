'''
Copyright (c) 2024 Justin Cornwell justin.cornwell@trojans.dsu.edu

Created Date: Wednesday, July 3rd 2024, 8:34:04 pm
Author: Justin Cornwell
----------------
Course: CSC842
Project/Lab: Cycle 9 - SHED v2 - Server
----------------
'''

# With pre-generated pyinstaller files
# - intake system IP list OR perform scan (must be one or the other, not both and not none)
# - Determine OS type
# - Launch checker with authrorized creds...
#  -- Windows (psexec as admin)
#  -- Mac/Linux (scp, ssh scripted? executable and .sh file?  sudo capes)

# graylog py????
# Is there a way to look for variations from baseline to end_engage?

import os
import argparse
import nmap
import datetime
from colorama import Fore, Back, Style

# Easier to run outside current directory
path = os.path.abspath(os.path.dirname(__file__))

def banner():
    print(f"{Fore.BLUE}      _______ _     _ _______ ______ \r\n\
      |______ |_____| |______ |     \\ \r\n\
      ______| |     | |______ |_____/   \r\n\
    {Fore.RED}\
  _______________________________ \r\n\
    || ____ ____ ____ _  _ ____ ____ || \r\n\
    || [__  |___ |__/ |  | |___ |__/ ||\r\n\
    || ___] |___ |  \\  \\/  |___ |  \\ ||\r\n\
    ||_______________________________||\
    {Fore.RESET}                          ")

def file_finder():
    # CLI and GUI file pickers
    f = "./here.txt"
    return f

def getIPs_cli(csv_list):
    targets = []
    ip_list = csv_list.split(',')
    for host in ip_list:
        #check if valid IP via re
        targets.append(host)
    return targets

def readIPs():
    f = file_finder()
    return f

def nmapHosts(target):
    # run nmap, return host and os_type
    # should run once or many times?
    # export data to 
    nm = nmap.PortScanner()
    nm.scan(target, '<port>')
    os_type = nm.scaninfo()
    return host, os_type

if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser(description="SHut Em Down (SHED)")
    parser.add_argument('-L','--list', help='Read in target IPs from file')
    parser.add_argument('-I','--IPs', help='Target IPs')
    parser.add_argument('-S', '--scan', help='Scan for Target IPs')
    parser.add_argument('-F', '--folder', action='store_true', help='Enable top folder picker')
    parser.add_argument('-C', '--cli', action='store_true', help='CLI only; disables GUI popups')      
    parser.add_argument('-G', '--graylog', help='Send data to graylog server \"http://127.0.0.1:9912/\"')  # v2, get from 
    parser.add_argument('-R', '--report', help='Save to local report file')                 # v2, how do you enforce? Tee to file? Save stdin, stdout, and stderr...
    args = parser.parse_args()

    targets = []

    # Create folder for each time run
    execution_folder = os.path.join(path, datetime.datetime())
    try:
        os.mkdir(execution_folder)
    except FileNotFoundError as e:
        print(f"Output folder could not be created: {execution_folder} ... {e}")
        exit
    # How to limit to only one of three...
    if args.list:
        print("From file")
        readIPs()
    elif args.IPs:
        print("From cli")
        targets = getIPs_cli(args.IPs)
    elif args.scan:
        print("From scan")
        ip_space = input("Provide IP space via CIDR notation")
        targets = nmapHosts()
    else:
        print(f"No target IPs provided...exiting")
        exit

    
