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

import subprocess, sys
import importlib.util
# Credited to work from Walt Del Orbe, https://github.com/DSUcyberops/csc842/tree/main/cycle8
# Function to check and install missing packages
def install_missing_packages(package_names):
    for package in package_names:
        if importlib.util.find_spec(package) is None:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
# Packages to check and install
required_packages = ["json", "nmap", "colorama", "paramiko", "scp"]
install_missing_packages(required_packages)

import os
import json
import argparse
import nmap
import datetime
import paramiko
import getpass
from pathlib import Path, PurePosixPath, PureWindowsPath
from scp import SCPClient
from colorama import init, Fore, Back, Style


start_date = ""
end_date = ""

# Easier to run outside current directory
path = os.path.abspath(os.path.dirname(__file__))

# fix colorama issue with Windows
init(convert=True)

# Out-of-scope safety net, excludes these IPs from test
no_strike_list = ['192.168.122.1']


def banner():
    print(f"{Fore.BLUE}      _______ _     _ _______ ______ \r\n\
      |______ |_____| |______ |     \\ \r\n\
      ______| |     | |______ |_____/   \r\n\
    {Fore.RED}\
  _______________________________ \r\n\
    || ____ ____ ____ _  _ ____ ____ || \r\n\
    || [__  |___ |__/ |  | |___ |__/ ||\r\n\
    || ___] |___ |  \\  \\/  |___ |  \\ ||\r\n\
    ||_______________________________||\r\n\
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

def readIPs(fileName, ip_list=[]):
    with open(fileName, mode='r') as file:
        for line in file:
            ip_list.append(line.strip())
    return ip_list

def nmapHosts(targets, execution_folder):
    try:
        # export data to 
        nm = nmap.PortScanner()
        arguments = '-Pn -O --osscan-guess --version-all'
        if no_strike_list:
            arguments = arguments + " --exclude " + ",".join(map(str, no_strike_list))
        print(arguments)
        # Ports 53,67,68,123 used to help identify systems up, but not open to remote connections on ports 22,135,139,445
        nm.scan(hosts=targets, ports='53,67,68,123,22,135,139,445', arguments=arguments)
        # Dump the scan results to JSON
        scan_json = nm.analyse_nmap_xml_scan()
        scan_json_str = json.dumps(scan_json, indent=4)
        
        # Write the JSON string to a file
        output_file = os.path.join(execution_folder, 'nmap_scan_results.json')
        with open(output_file, 'w') as f:
            f.write(scan_json_str)
 
        # Parse the JSON
        scan_data = json.loads(scan_json_str)
        if not scan_data['scan']:
            print("No devices detected...exiting")
            return
        # Define Apple default naming convention for bypassing fingerprint
        apples = ["s-air", "s-imac", "s-mbp"]
        
        ssh_list = {}
        win_list = {}
        
        for host, result in scan_data['scan'].items():
            print(f'Host:: {Fore.GREEN}{host}{Fore.RESET}')
            host_os = "Unknown"             # Default to Unknown value pending tests
            hostname = "Unknown"


            # Display Hostname if available
            if 'hostnames' in result:
                for item in result['hostnames']:
                    hostname = item['name']
                    print(f"Hostname:: {Fore.BLUE}{hostname}{Fore.RESET}")

            # Display the OS type if available; exclude custom rulesets before pulling osfamily value from NMap
            # Need to find a way to dictate the top result of the nmap scan
            if "iphone" in hostname:
                host_os = "Apple iOS"
            elif any(var in hostname for var in apples):
                host_os = "Apple macOS" 
            elif "xbox" in hostname:
                host_os = "Windows for XBox"
            else:
                if 'osmatch' in result:
                    for osmatch in result['osmatch']:
                        for osclass in osmatch['osclass']:
                            host_os = osclass['osfamily']
            print(f"OS Type:: {Fore.MAGENTA}{host_os}{Fore.RESET}")    

            # Cycle through port status
            if 'tcp' in result:
                print('Open TCP ports:')
                for port in result['tcp']:
                    if result['tcp'][port]['state'] =='open':
                        service_name = result['tcp'][port]['name']
                        print(f'Port: {port}, Service: {service_name}, State: {result["tcp"][port]["state"]}')
                        if "ssh" in service_name.lower():
                            ssh_list[host] = {'hostname': hostname, 'service': service_name, 'port': port, 'OS': host_os}
                        if "netbios-ssn" in service_name.lower() or "microsoft-ds" in service_name.lower():
                            win_list[host] = {'hostname': hostname, 'service': service_name, 'port': port, 'OS': host_os}
            if 'udp' in result:
                print('Open UDP ports:')
                for port in result['udp']:
                    if result['udp'][port]['state'] =='open':
                        print(f'Port: {port}, State: {result["udp"][port]["state"]}')
            print()
        test_systems = {"ssh": ssh_list, "psexec": win_list}
        return test_systems
    except nmap.PortScannerError as e:
        print(f'PortScannerError: {e}')
    except Exception as e:
        print(f'An unexpected error occurred: {e}')

#################################################################################################### ssh to systems 
def create_ssh_client(hostname, port, username, password):
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, port=port, username=username, password=password)
    return ssh

def upload_file_via_scp(ssh, local_path, remote_path):
    with SCPClient(ssh.get_transport()) as scp:
        scp.put(local_path, remote_path)

def ssh_to(ip, port, OS):
    global start_date, end_date
    
    username = input('User: ')
    password = getpass.getpass(prompt="Enter SSH password: ")
    path_elements = []
    file = "shutemdown"
   
    # Normal use of os.path is bad when writing for a different os target than the os for host
    if "win" in OS.lower():
        path_elements = ['C', 'Windows', 'Temp', file]
        remote_path = PureWindowsPath(*path_elements)
        target_os = 'windows'
    else:
        path_elements = ['/tmp', file]
        remote_path = PurePosixPath(*path_elements)
        if 'macOS' in OS:
            target_os = 'macos'
        elif "iOS" in OS:
            print('Target not supported...')
            return
        else:
            target_os = 'linux'

    local_path = os.path.join(path, "dist", target_os, file)
    try:
        # Connect to the server
        ssh = create_ssh_client(ip, port, username, password)
        upload_file_via_scp(ssh, local_path, remote_path)
        #top_folder = input("Top Folder: ")

        # Execute the command
        ssh.exec_command(f'chmod +x {str(remote_path)}')
        '''
        cmd = f'{str(remote_path)} --cli --start 07/01/24 --end 07/15/24 --location /tmp'
        print(cmd)
        log_file = f'/tmp/SHED{datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.out'
        stdin, stdout, stderr = ssh.exec_command(f'echo {password} | sudo -S bash -l -c "{cmd} > {log_file}"')
        '''
        stdin, stdout, stderr = ssh.exec_command(f'echo {password} | sudo -S /tmp/script.sh')

        # Read and print the output
        output = stdout.read().decode()
        print(f"Output: {output}")

        # Read and print any error messages
        error = stderr.read().decode()
        if error:
            print(f"Error: {error}")

    finally:
        #stdin, stdout, stderr = ssh.exec_command(f'rm -f {remote_path}')
        
        # Read the output and error streams
        #output = stdout.read().decode()
        #error = stderr.read().decode()
        
        # Close the connection
        ssh.close()


if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser(description="SHut Em Down (SHED) Server")
    parser.add_argument('-S','--start', help='Engagement Window Start Date [MM/DD/YY]')
    parser.add_argument('-E','--end', help='Engagement Window End Date [MM/DD/YY]')
    parser.add_argument('-G', '--graylog', help='Send data to graylog server \"http://127.0.0.1:9912/\"')  # v2, remove?
    parser.add_argument('--location', help='Scan for target IPs')

    # Limit to one of the following 3 options for IP processing
    IP_group = parser.add_mutually_exclusive_group(required=True)
    IP_group.add_argument('-L','--list', type=str, help='Read in target IPs from file')
    IP_group.add_argument('-I','--IPs', type=str, help='Comma seperated list of target IPs')
    IP_group.add_argument('--scan', action='store_true', help='Scan for target IPs')
 
    args = parser.parse_args()

    targets = []

    # Create folder for each time run
    execution_folder = os.path.join(path, datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
    try:
        os.mkdir(execution_folder)
    except FileNotFoundError as e:
        print(f"Output folder could not be created: {execution_folder} ... {e}")
        exit


    start_engage = args.start
    end_engage = args.end
    top_folder = args.location

    if args.list:
        targets = readIPs(args.list)
    elif args.IPs:
        targets = getIPs_cli(args.IPs)
    elif args.scan:
        targets.append(input("Provide IP space via CIDR notation:  "))
    else:
        print(f"No target IPs provided...exiting")
        exit
    
    test_systems = nmapHosts(','.join(targets), execution_folder)
    print(test_systems)

    # Loop through the top-level keys
    for category, systems in test_systems.items():
        print(f"Category: {category}")
        # Loop through the nested dictionaries
        for ip, details in systems.items():
            print(f"IP Address: {ip}")
            print(f"Hostname: {details['hostname']}")
            print(f"Service: {details['service']}")
            print(f"OS: {details['OS']}")
            ssh_to(ip, details['port'], details['OS'])