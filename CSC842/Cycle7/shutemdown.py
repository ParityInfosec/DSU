'''
Copyright (c) 2024 Justin Cornwell justin.cornwell@trojans.dsu.edu

Created Date: Tuesday, June 25th 2024, 8:12:31 pm
Author: Justin Cornwell
----------------
Course: CSC842
Project/Lab: Cycle 7 - SHut Em Down (SHED)
----------	---	----------------------------------------------------------
'''

global import_failure
import_failure = False
import os
import re
import socket
import subprocess
import argparse
import psutil
import platform                 # Much better than os for cross platform
import pytz
import json
from prettytable import PrettyTable
from datetime import datetime
# Test for imports tied to GUIs; fail back to CLI and continue if not available
try:
    import tkinter as tk
    from babel import numbers
    from tkcalendar import Calendar
    from tkinter import ttk, filedialog
except ImportError:
    print(f"Warning: Could not import {module_name}. GUI options not available.")
    import_failure = True

# Easier to run outside current directory
path = os.path.abspath(os.path.dirname(__file__))

#################################################### Display / UI 
# Custom pretty print header format
def print_head(header):
    print("\n\r" + "=" *95)
    print(f"{header}")
    print("=" *95)


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
    root.title("Tkinter Folder Picker Example")
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

#################################################### User tools 
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
            #return creation_date.strftime('%Y-%m-%d %H:%M:%S')
            return creation_date.strftime('%m/%d/%y')
        else:
            print(f"Could not find creation date for folder: {folder_path}")
            return None
    except Exception as e:
        print(f"Error occurred: {e}")
        return None

def get_linux_folder_creation_date(user):
    try:
        home_dir = f'/home/{user}'
        result = subprocess.run(['stat', home_dir], stdout=subprocess.PIPE, text=True)
        output = result.stdout
        # Using regular expression to extract the creation date
        match = re.search(r'Birth: (.+)', output)
        if match:
            creation_date_str = match.group(1).strip()
            creation_date = datetime.strptime(creation_date_str, '%Y-%m-%d %H:%M:%S.%f %z')
            return creation_date.strftime('%m/%d/%y')
        return None
    except Exception as e:
        print(f"Error occurred: {e}")
        return None



def check_hosts(filename):
    # Open the file using 'with' to ensure it gets closed after reading
    with open(filename, 'r') as file:
        # Iterate over each line in the file
        for line in file:
            # Only print lines with DNS entries
            if not line.startswith("#"):
                print(line.strip())

def check_connects():
    # Create a table with the desired columns
    table = PrettyTable()
    table.field_names = ["Local Address", "Local Port", "Status", "PID", "Process"]

    # Fetch all inet connections (TCP/UDP over IPv4/IPv6)
    connections = psutil.net_connections(kind='inet')

    # Process each connection to find any listeners
    for conn in connections:
        if conn.status == 'LISTEN':
            # Prepare local and remote addresses
            laddr = f"{conn.laddr.ip}" if conn.laddr else "N/A"
            lport = f"{conn.laddr.port}" if conn.laddr else "N/A"
            pname = f"{psutil.Process(conn.pid).name()}"
            # Add a row to the table
            table.add_row([laddr, lport, conn.status, conn.pid, pname])

    # Print the table
    print(table)

def check_file(file, start_date, end_date):   # Not working
    create = os.path.getctime(file)
    access = os.path.getatime(file)
    modify = os.path.getmtime(file)

    date_format = "%m/%d/%y"
    create_date = datetime.fromtimestamp(create, pytz.UTC).strftime(date_format)
    access_date = datetime.fromtimestamp(access, pytz.UTC).strftime(date_format)
    modify_date = datetime.fromtimestamp(modify, pytz.UTC).strftime(date_format)
    
    results = []
    if is_date_between(create_date,start_date,end_date):
        results.append([True, "Create", create_date])
    if is_date_between(access_date,start_date,end_date):
        results.append([True, "Access", create_date])
    if is_date_between(modify_date,start_date,end_date):
        results.append([True, "Modify", create_date])
    return results

def check_files(top_folder):
    filesTable = PrettyTable()
    filesTable.field_names = ["File", "Type", "Date", "Executable?"]
    for root, dirs, files in os.walk(top_folder):
        for file in files:
            filepath = os.path.join(root, file)
            results = check_file(filepath, start_engage, end_engage)             # Not working
            for i in results:
                if os.access(filepath, os.X_OK):
                    is_executable = True 
                else:
                    is_executable = False
                filesTable.add_row([filepath, i[1], i[2], is_executable])
    print(filesTable)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SHut Em Down (SHED)")
    parser.add_argument('-S','--start', help='Engagement Window Start Date [MM/DD/YY]')
    parser.add_argument('-E','--end', help='Engagement Window End Date [MM/DD/YY]')
    parser.add_argument('-L', '--location', help='Set top folder for checks, default: root [/ or c:\\]')   # Set to . for testing phase
    parser.add_argument('-F', '--folder', action='store_true', help='Enable top folder picker')
    parser.add_argument('-G', '--gui', action='store_true', help='Enable GUI display')      # Not functioning yet
    args = parser.parse_args()

    print_head("System Details...")
    if platform.system() == "Linux":
        OS_type = "Linux"
        hostsFile = "/etc/hosts"
    elif platform.system() == "Darwin":
        OS_type = "MacOS"
        hostsFile = "/etc/hosts"
    elif platform.system() == "Windows":
        OS_type = "Windows"
        hostsFile = "C:\\Windows\\System32\\drivers\\etc\\hosts"
    print(OS_type)
    print(platform.node())
    ipv4s = get_ips()
    for ip in ipv4s:
        print(ip)

    start_engage = args.start
    end_engage = args.end
    top_folder = args.location

    print_head("Engagement Window")
    if args.gui or import_failure:
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
        if not(start_engage):
            start_engage = select_date("Select Start Date")
        if not(end_engage):
            end_engage = select_date("Select End Date")
        print(f"Start: {start_engage}")
        print(f"End: {end_engage}")
        print_head("Folder Structure...")
        if not(top_folder):
            top_folder = '.'
        if args.folder:
            top_folder = open_folder_picker()
        print(top_folder)
    
    print_head("Checking hosts files...")
    check_hosts(hostsFile)

    print_head("Checking for New Accounts...")
    if OS_type == "Linux":
        hostsFile = "/etc/hosts"
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
        user_creation_dates = get_win_user_creation_dates()
        print(user_creation_dates)
        try:
            for user, crate_date in user_creation_dates:
                print(user, create_date)
                date_format = "%m/%d/%y"
                create_date = datetime.fromtimestamp(user['CreationDate'], pytz.UTC).strftime(date_format)
                print(create_date)
                if user_creation_dates:
                    for user, creation_date in user_creation_dates:
                        print(f"User: {user}, Created on: {creation_date}")
                else:
                    print("No user creation dates found or error occurred")
        except:      
            print(f"Error: Check Users Manually")


    print_head("Checking for Listeners...")
    check_connects()

    print_head("Checking files for changes during engagment window...")
    check_files(top_folder)