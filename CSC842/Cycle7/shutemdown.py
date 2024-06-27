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
import socket
import argparse
import psutil
import platform                 # Much better than os for cross platform
from prettytable import PrettyTable
from datetime import datetime
# Test for imports tied to GUIs; fail back to CLI and continue if not available
try:
    import tkinter as tk
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

def get_date(prompt="Enter the date (MM/DD/YY): "):
    while True:
        date_str = input(prompt)
        try:
            # Try to convert the string to a datetime object
            date_in = datetime.datetime.strptime(date_str, "%m/%d/%Y")
            return date_in
        except ValueError:
            print("Invalid date format. Please try again.")

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
    '''
    if modify < create or access < create:
        print('***** Potential Timestomp ******')
    '''

    date_format = "%m/%d/%y"
    in_window,is_executable, poss_stomp = False, False, False
    # Parse the date string into a datetime object
    start = int(datetime.strptime(start_date, date_format).timestamp())
    end = int(datetime.strptime(end_date, date_format).timestamp())

    if create < end and create > start:
        print(f"created {file} on {create}, in window")
        in_window = True
    if access < end and access > start:
        print(f"accessed {file} on {access}, in window")
        in_window = True
    if modify < end and modify > start:
        print(f"modified {file} on {modify}, in window")
        in_window = True
    if os.access(file, os.X_OK) and in_window:
        print(f"{file} is executable & in window")
        is_executable = True    
    return in_window, is_executable, poss_stomp
    

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

    print_head("Checking for Listeners...")
    check_connects()
    
    count = 0
    engagement_files = []
    executable_files = []

    print_head("Checking files for changes during engagment window...")
    for root, dirs, files in os.walk(top_folder):
        for file in files:
            filepath = os.path.join(root, file)
            in_window, is_executable, poss_stomp = check_file(filepath, start_engage, end_engage)             # Not working
            if in_window:
                engagement_files.append(filepath)
            if is_executable:
                executable_files.append(filepath)
        count += 1
    print(count)
    print_head("Results Array...")
    print(engagement_files)
    print_head("Files in engagment that were executable...")
    print(executable_files)