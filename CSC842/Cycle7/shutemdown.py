'''
Copyright (c) 2024 Justin Cornwell justin.cornwell@trojans.dsu.edu

Created Date: Tuesday, June 25th 2024, 8:12:31 pm
Author: Justin Cornwell
----------------
Course: CSC842
Project/Lab: Cycle 7 - SHut Em Down (SHED)
----------	---	----------------------------------------------------------
'''

import os
import argparse
import psutil
import platform                 # Much better than os for cross platform
import tkinter as tk
from prettytable import PrettyTable
from datetime import datetime
from tkcalendar import Calendar
from tkinter import ttk, filedialog

# Easier to run outside current directory
path = os.path.abspath(os.path.dirname(__file__))

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
            initialdir="/",  # Set to your preferred starting directory
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
            # Check if the line starts with the specified string
            if line.startswith("127.0.0.1"):
                # Print the line, stripping newline characters for clean output
                print(line.strip())

def check_connects():
    # Create a table with the desired columns
    table = PrettyTable()
    table.field_names = ["Local Address", "Remote Address", "Status", "PID"]

    # Fetch all inet connections (this includes TCP and UDP over IPv4 and IPv6)
    connections = psutil.net_connections(kind='inet')

    # Process each connection
    for conn in connections:
        # Prepare local and remote addresses
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"

        # Add a row to the table
        table.add_row([laddr, raddr, conn.status, conn.pid])

    # Print the table
    print(table)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SHut Em Down (SHED)")
    parser.add_argument('-S','--start', help='Engagement Window Start Date [MM/DD/YY]')
    parser.add_argument('-E','--end', help='Engagement Window End Date [MM/DD/YY]')
    parser.add_argument('-L', '--location', help='Set top folder for checks, default: root [/ or c:\\]')
    parser.add_argument('-F', '--folder', action='store_true', help='Enable top folder picker')
    parser.add_argument('-G', '--gui', action='store_true', help='Enable GUI display')      # Not functioning yet
    args = parser.parse_args()

    if platform.system() == "Linux":
        hostsFile = "/etc/hosts"
    elif platform.system() == "Windows":
        hostsFile = "C:\\Windows\\System32\\drivers\\etc\\hosts"

    start_engage = args.start
    end_engage = args.end
    top_folder = args.location

    if not(start_engage):
        start_engage = select_date("Select Start Date")
    if not(end_engage):
        end_engage = select_date("Select End Date")
    if not(top_folder):
        top_folder = '/'
    if args.folder:
        top_folder = open_folder_picker()
   
    # Print headers/breaks
    check_hosts(hostsFile)
    # Print headers/breaks
    check_connects()
    count = 0
    print(start_engage, end_engage, top_folder)
    for _, dirs, _ in os.walk(top_folder):
        count += 1
    print(count)