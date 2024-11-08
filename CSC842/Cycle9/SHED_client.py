'''
Copyright (c) 2024 Justin Cornwell justin.cornwell@trojans.dsu.edu

Created Date: Wednesday, July 3rd 2024, 7:21:31 pm
Author: Justin Cornwell
----------------
Course: CSC842
Project/Lab: Cycle 9 - SHut Em Down (SHED) v2 Client
----------	---	----------------------------------------------------------
'''

import os
import socket
import subprocess, sys
import argparse
import importlib.util

global import_failure
import_failure = False
def install_missing_packages(package_names):
    for package in package_names:
        if importlib.util.find_spec(package) is None:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
# Packages to check and install
required_packages = ["re", "ctypes", "psutil", "platform", "pytz", "colorama", "prettytable", "json"]
install_missing_packages(required_packages)


import re
import json
import ctypes
import psutil
import platform                 # Much better than os for cross platform
import pytz
from colorama import init, Fore, Back, Style
from prettytable import PrettyTable
from datetime import datetime

# Test for imports tied to GUIs; fail back to CLI and continue if not available
try:
    import tkinter as tk
    from babel import numbers
    from tkcalendar import Calendar
    from tkinter import ttk, filedialog
except ImportError as e:
    print(f"Warning: Could not import: {e}. GUI options not available.")
    import_failure = True

# fix colorama issue with Windows
init(autoreset=True)

#################################################### TTPs; change to teams' SOPs or habits 
sus_procs = {'nc', "python", "python3", "php", 'nc.exe', 'ncat.exe', 'python.exe', 'python3.exe'}
sus_ports = {'4444','5555','6666','7777','8888','9999','9998','9997','9996'}

# Easier to run outside current directory
path = os.path.abspath(os.path.dirname(__file__))

#################################################### Display / UI 
# Custom pretty print header format
def print_head(header):
    print(Fore.RED + f"\n\r" + "=" *95)
    print(Fore.BLUE + f"{header}")
    print(Fore.RED + "=" *95)


def select_date(title_msg):
    # Create a popup window
    popup = tk.Tk()
    popup.title(title_msg)
    popup.geometry("300x300")

    # Variable to store the selected date
    selected_date = {}

    # Create a calendar widget
    cal = Calendar(popup, selectmode='day', year=datetime.now().year, month=datetime.now().month, day=datetime.now().day)
    cal.pack(pady=20)

    # Function to handle closing the popup
    def on_close():
        selected_date['date'] = cal.get_date()  # Store the date in the dictionary
        popup.destroy()

    # Button to choose today's date
    ttk.Button(popup, text="Select Today", command=lambda: cal.selection_set(datetime.now().date())).pack()
    
    # Button to confirm the selection
    ttk.Button(popup, text="OK", command=on_close).pack()

    popup.mainloop()
    return selected_date.get('date')  # Retrieve the date from the dictionary

def open_folder_picker():
    # Create the main window
    root = tk.Tk()
    root.title("Folder Picker")
    root.geometry("600x100")

    # Variable to store the selected folder path
    folder_path = ""

    # Function to handle folder selection
    def select_folder():
        nonlocal folder_path
        foldername = filedialog.askdirectory(
            initialdir=".",  # Set to your preferred starting directory
            title="Select a folder"
        )
        folder_path = foldername if foldername else "No folder selected"
        root.destroy()  # Close the window only after retrieving the folder path

    # Add a button to open the folder picker dialog
    open_folder_btn = ttk.Button(root, text="Select Folder", command=select_folder)
    open_folder_btn.pack(pady=20)

    # Start the GUI event loop
    root.mainloop()

    # Return the folder path
    return folder_path

def get_date(prompt="Enter the date (MM/DD/YY): "):
    while True:
        date_str = input(prompt)
        try:
            # Try to convert the string to a datetime object
            date_in = datetime.strptime(date_str, "%m/%d/%y")
            date_in= date_in.strftime('%m/%d/%y')
            return date_in
        except ValueError:
            print("Invalid date format. Please try again.")

def is_date_between(date_str, start_date_str, end_date_str):
    date = datetime.strptime(date_str, '%m/%d/%y')
    start_date = datetime.strptime(start_date_str, '%m/%d/%y')
    end_date = datetime.strptime(end_date_str, '%m/%d/%y')
    return start_date <= date <= end_date

def get_directory(prompt="Please enter a directory path: "):
    while True:
        directory = input(prompt)
        # Check if the provided path is a valid directory
        if os.path.isdir(directory):
            return directory
        else:
            print(f"Error: '{directory}' is not a valid directory. Please try again.")

def get_ips():
    ip_addresses = []
    for interface_name, interface_addresses in psutil.net_if_addrs().items():
        for address in interface_addresses:
            if address.family == socket.AF_INET:
                ip_addresses.append(address.address)
    return ip_addresses

def get_sys_params():
    if platform.system() == "Linux":
        OS_type = "Linux"
        hostsFile = "/etc/hosts"
        user_root = "/home"
    elif platform.system() == "Darwin":
        OS_type = "MacOS"
        hostsFile = "/etc/hosts"
        user_root = "/Users"
    elif platform.system() == "Windows":
        OS_type = "Windows"
        hostsFile = "C:\\Windows\\System32\\drivers\\etc\\hosts"
        user_root = "C:\\Windows\\Users"
    else:
        exit(f"ERROR: This system type is not supported.  Exiting...")
    return OS_type, hostsFile, user_root

#################################################### User tools 
def get_linux_users(users_JSON={}):
    user_list = get_linux_users_from_passwd()
    print("Cannot determine account creation...manually check the following users...")
    for user in user_list:
        print(f"- {user}")
        users_JSON[f'{user}'] = {'Creation Date': 'N/A'}
    return users_JSON

def get_win_users(users_JSON={}):
    user_creation_dates = get_win_user_creation_dates()
    try:
        no_create = 0
        for user, create_date in user_creation_dates:
            if create_date:
                create_date = datetime.strptime(create_date, '%m/%d/%Y %H:%M:%S')
                create_date = create_date.strftime('%m/%d/%y')
                user_str = f"{user}, Created on: {create_date}"
                users_JSON[user] = {'Creation Date': create_date}
                if is_date_between(create_date, start_engage, end_engage):
                    user_str = Fore.YELLOW + Back.RED + user_str
            else:
                user_str = f"User: {user}"
                users_JSON[user] = {'Creation Date': 'N/A'}

                no_create += 1
            print(user_str)
        if no_create == len(user_creation_dates):
            print(Fore.LIGHTMAGENTA_EX + "No records show user addition; verify usernames above if outside log retention window")        
    except:      
        print(f"Error: Check Users Manually")
    return users_JSON

def get_win_user_creation_dates():
    # PowerShell command to get all users and their creation dates
    command = (
        "Get-LocalUser | "
        "ForEach-Object { "
        "  $user = $_; "
        "  $createdDate = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720} | "
        "    Where-Object { $_.Properties[0].Value -eq $user.Name } | "
        "    Select-Object -First 1 -ExpandProperty TimeCreated); "
        "  \"$($user.Name),$($createdDate)\" "
        "}"
    )

    result = subprocess.run(['powershell', '-Command', command], stdout=subprocess.PIPE, text=True)
    
    # Check if the command executed successfully
    if result.returncode != 0:
        print("Error executing PowerShell command")
        return []

    # Check if stdout is empty
    if not result.stdout.strip():
        print("No output from PowerShell command")
        return []

    # Parse the output into a set of tuples
    user_creation_dates = set()
    for line in result.stdout.splitlines():
        parts = line.split(',')
        if len(parts) == 2:
            username, creation_date = parts
            user_creation_dates.add((username.strip(), creation_date.strip()))
    
    return user_creation_dates

def get_macos_user_list():
    try:
        result = subprocess.run(['dscl', '.', 'list', '/Users'], stdout=subprocess.PIPE, text=True)
        users = result.stdout.splitlines()
        
        # Filter out system users
        user_list = [user for user in users if not user.startswith('_') and user != 'root']
        
        return user_list
    except Exception as e:
        print(f"Error occurred: {e}")
        return []

def get_mac_folder_creation_date(user):
    try:
        folder_path = "/Users/" + user
        # Run the mdls command to get metadata about the folder
        result = subprocess.run(['mdls', '-name', 'kMDItemFSCreationDate', folder_path], stdout=subprocess.PIPE, text=True)
        
        # Parse the output to extract the creation date
        output = result.stdout.strip()
        match = re.search(r'kMDItemFSCreationDate\s=\s(.+)', output)
        if match:
            creation_date_str = match.group(1).strip()
            creation_date = datetime.strptime(creation_date_str, '%Y-%m-%d %H:%M:%S %z')
            return creation_date.strftime('%m/%d/%y')
        else:
            print(f"Could not find creation date for folder: {folder_path}")
            return None
    except Exception as e:
        print(f"Error occurred: {e}")
        return None

def get_linux_users_from_passwd():
    users = []
    with open('/etc/passwd', 'r') as passwd_file:
        for line in passwd_file:
            parts = line.split(':')

            # What if user is <= 1000?
            if len(parts) > 1 and int(parts[2]) >=1000:
                username = parts[0]
                users.append(username)
            '''
            if len(parts) > 1 and int(parts[2]) >=1000:
                username = parts[0]
                create_date = get_home_creation(username)
                users.append(username, create_date)
            '''
    return users

def get_home_creation(user, user_root):
    user_folder = os.path.join(user_root, user)
    # Check home folder creation, if exists
    try:
        stat_info = os.stat(user_folder)
        if hasattr(stat_info, 'st_birthtime'):
            # For Unix
            creation_time = stat_info.st_birthtime
        else:
            # For Windows and other systems that do not have st_birthtime
            creation_time = stat_info.st_ctime
        creation_date = datetime.datetime.fromtimestamp(creation_time)
        return creation_date
    except FileNotFoundError:
        print(f"- {user} has no home directory.")
        return None

def check_hosts(filename):
    # Open the file using 'with' to ensure it gets closed after reading
    with open(filename, 'r') as file:
        # Iterate over each line in the file
        for line in file:
            # Only print lines with DNS entries
            if not line.startswith("#"):
                print(line.strip())

def check_connects(connects_JSON={}):
    # Create a table with the desired columns
    table = PrettyTable()
    table.field_names = ["Local Address", "Local Port", "Remote Address", "Remote Port", "Status", "PID", "Process"]
    

    # Fetch all inet connections (TCP/UDP over IPv4/IPv6)
    connections = psutil.net_connections(kind='inet')

    ################################# v2
    # - Capture suspect processes also [done]
    # - Capture add'l details for logging (poss using oneshot?)
    #   -- Get full command with arguments (important for b64 options)

    # Process each connection to find any listeners
    for conn in connections:
        if conn.status == 'LISTEN' or psutil.Process(conn.pid).name() in sus_procs or (conn.laddr and conn.laddr.port in sus_ports) or (conn.raddr and conn.raddr.port in sus_ports):
            # Prepare local and remote addresses
            laddr = f"{conn.laddr.ip}" if conn.laddr else "N/A"
            lport = f"{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}" if conn.raddr else "N/A"
            rport = f"{conn.raddr.port}" if conn.raddr else "N/A"
            pname = f"{psutil.Process(conn.pid).name()}"

            key = f'{laddr}_{lport}'
            connects_JSON[key] = {
                table.field_names[0]: laddr, 
                table.field_names[1]: int(lport) if lport != "N/A" else lport, 
                table.field_names[2]: raddr, 
                table.field_names[3]: int(rport) if rport != "N/A" else rport, 
                table.field_names[4]: conn.status, 
                table.field_names[5]: conn.pid, 
                table.field_names[6]: pname
            }
            if psutil.Process(conn.pid).name() in sus_procs:
                pname = Fore.YELLOW + Back.RED + pname + Style.RESET_ALL
            if lport in sus_ports:
                lport = Fore.YELLOW + Back.RED + f'{lport}' + Style.RESET_ALL
            if rport in sus_ports:
                rport = Fore.YELLOW + Back.RED + f'{rport}' + Style.RESET_ALL
            # Add a row to the table
            table.add_row([laddr, lport, raddr, rport, conn.status, conn.pid, pname])

    # Print the table
    table.sortby = "Local Port"
    print(table)
    return connects_JSON

def isTimeStomped(create_date, modify_date):
    # SANS FOR610, deconflict the create/modify dates along with inodes around 
    # Can you pull dates by looking for inodes regardless of folders?

    return False

def isTypeMismatch():
    # Using Magic Types
    
    return False

def isSusType(file):
    # Determine if the file type is commonly used in team tools
    return False

def check_file(file, start_date, end_date): 
    try:
        create = os.path.getctime(file)
        modify = os.path.getmtime(file)
        date_format = "%m/%d/%y"
        create_date = datetime.fromtimestamp(create, pytz.UTC).strftime(date_format)
        modify_date = datetime.fromtimestamp(modify, pytz.UTC).strftime(date_format)

        results = []
        if is_date_between(create_date,start_date,end_date):
            results.append([True, "Create", create_date])
        if is_date_between(modify_date,start_date,end_date):
            results.append([True, "Modify", modify_date])
        if isTimeStomped(create_date, modify_date):
            results.append([False, "!!Time Stomped!!", "N/A"])
        return results
    except FileNotFoundError as e:
        return []
    except PermissionError as p:
        print(f'{p}: {file}')
    


def check_files(top_folder, files_JSON={}):
    filesTable = PrettyTable()
    filesTable.field_names = ["File", "Type", "Date", "Executable?"]
   
    for root, dirs, files in os.walk(top_folder):
        for file in files:
            filepath = os.path.join(root, file)

            results = check_file(filepath, start_engage, end_engage)
            for i in results:
                if OS_type == "Linux" or OS_type == "MacOS":
                    if os.access(filepath, os.X_OK):
                        is_executable = True 
                    else:
                        is_executable = False
                # I don't think this is actually functioning correctly
                if OS_type == "Windows":    
                    GetFileAttributes = ctypes.windll.kernel32.GetFileAttributesW
                    attributes = GetFileAttributes(filepath)
                    FILE_ATTRIBUTE_SYSTEM = 0x04
                    if attributes & FILE_ATTRIBUTE_SYSTEM >= 1:
                        is_executable = True
                    else:
                        is_executable = False
                filesTable.add_row([filepath, i[1], i[2], is_executable])
                files_JSON[filepath] = {
                    filesTable.field_names[1]: i[1], 
                    filesTable.field_names[2]: i[2], 
                    filesTable.field_names[3]: is_executable
                }
    filesTable.sortby = "Type"
    filesTable.reversesort = True
    filesTable.max_width = 88
    print(filesTable)
    return files_JSON

def write_to_file(execution_folder, filename, content):
        output_file = os.path.join(execution_folder, filename)
        with open(output_file, 'w') as f:
            f.write(content)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SHut Em Down (SHED) - Client")
    parser.add_argument('-S','--start', help='Engagement Window Start Date [MM/DD/YY]')
    parser.add_argument('-E','--end', help='Engagement Window End Date [MM/DD/YY]')
    parser.add_argument('-L', '--location', help='Set top folder for checks, default: root [/ or c:\\]')
    parser.add_argument('-F', '--folder', action='store_true', help='Enable top folder picker')
    parser.add_argument('-C', '--cli', action='store_true', help='CLI only; disables GUI popups')      
    parser.add_argument('-R', '--report', required=True, help='Save to local report file')
    args = parser.parse_args()

    date_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    if args.report:
        # Create save file
        # Start outputting data to report_file
        # Create folder for each time run
        execution_folder = os.path.join(args.report, "SHED")
        if not os.path.exists(execution_folder):
            try:
                os.mkdir(execution_folder)
            except FileNotFoundError as e:
                print(f"Output folder could not be created: {execution_folder} ... {e}")
                exit
        
    print_head(f"System Details...{date_time}")
    OS_type, hostsFile, user_root = get_sys_params() 
    print(f"Current User: {Fore.BLUE}{os.getlogin()}")
    print(f"OS: {OS_type}")
    print(f"Hostname: {Fore.MAGENTA}{platform.node()}")
    ipv4s = get_ips()
    ip_set = []
    for ip in ipv4s:
        ip_set.append(ip)
        if not str(ip).startswith("169.254") and not str(ip) == "127.0.0.1":
            ip = Fore.GREEN + ip
        print(ip)

    details_JSON = {"Hostname": platform.node(),
                    "Date/Time": date_time,
                    "Current User": os.getlogin(),
                    "OS": OS_type,
                    "IPs": ip_set
                    }

    start_engage = args.start
    end_engage = args.end
    top_folder = args.location

    print_head("Engagement Window...")
    if args.cli or import_failure:
        if not(start_engage):
            print("Enter Start Date")
            start_engage = get_date()
        if not(end_engage):
            print("Enter End Date")
            end_engage = get_date()
        print(f"Start: {start_engage}")
        print(f"End:   {end_engage}")
        print_head("Folder Structure...")
        if not(top_folder):
            top_folder = get_directory()
        if args.folder:
            print("Folder picker not available in GUI mode.")
            top_folder = get_directory()
        print(top_folder)
    else:
        while start_engage == None:                                       
            start_engage = select_date("Select Start Date")
        while end_engage == None:                                         
            end_engage = select_date("Select End Date")
        print(f"Start: {start_engage}")
        print(f"End: {end_engage}")
        print_head("Folder Structure...")
        if not(top_folder):
            top_folder = open_folder_picker()
        print(top_folder)
    
    print_head("Checking hosts files...")
    check_hosts(hostsFile)

    print_head("Checking for New Accounts...")                  # Add methods to find if things exist
    if OS_type == "Linux":
        users_JSON = get_linux_users()
    elif OS_type == "MacOS":
        # Get user list
        user_list = get_macos_user_list()

        # Display the results
        print("User accounts and their addition dates:")
        for user in user_list:
            user_date = get_mac_folder_creation_date(user)
            if user_date != None and is_date_between(user_date, start_engage, end_engage):
                    print(f"{user} : {user_date}")
        if not user_list:
            print("No user accounts found or error occurred.")    
    elif OS_type == "Windows":
        users_JSON = get_win_users()

    print_head("Checking for Listeners...")
    connects_JSON = check_connects()

    print_head("Checking files for changes during engagment window...")
    files_JSON = check_files(top_folder)
    system_results = {"Details": details_JSON,
                      "Connections": connects_JSON, 
                      "Files": files_JSON,
                      "Users": users_JSON
                      }
    # print(json.dumps(details_JSON, indent=4))
    print(f'JSON stored at: {execution_folder}/results.shed')
    write_to_file(execution_folder, "results.shed", json.dumps(system_results, indent=4))