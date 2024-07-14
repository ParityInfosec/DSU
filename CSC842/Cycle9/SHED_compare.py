'''
Copyright (c) 2024 Justin Cornwell justin.cornwell@trojans.dsu.edu

Created Date: Saturday, July 13th 2024, 10:20:20 pm
Author: Justin Cornwell
----------------
Course: CSC842
Project/Lab: Cycle9 - SHED v2 - JSON compare 
----------	---	----------------------------------------------------------
'''

import os
import json
import argparse
from colorama import init, Fore, Back, Style

# Test for imports tied to GUIs; fail back to CLI and continue if not available
global import_failure
import_failure = False
try:
    import tkinter as tk
    from tkinter import ttk, filedialog
except ImportError as e:
    print(f"Warning: Could not import: {e}. GUI options not available.")
    import_failure = True

# fix colorama issue with Windows
init(autoreset=True)

def get_file(prompt="Please enter a file path: "):
    while True:
        filename = input(prompt).strip()
        # Check if the provided path is a valid directory
        if os.path.exists(filename):
            return filename
        else:
            print(f"Error: '{filename}' is not a valid file. Please try again.")

def load_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def compare_json(json1, json2, path=""):
    differences = []

    if isinstance(json1, dict) and isinstance(json2, dict):
        keys1 = set(json1.keys())
        keys2 = set(json2.keys())

        for key in keys1.union(keys2):
            new_path = f"{path}/{key}" if path else key
            if key in json1 and key in json2:
                differences.extend(compare_json(json1[key], json2[key], new_path))
            elif key in json1:
                differences.append(f"Key {Fore.GREEN}'{new_path}'{Fore.BLUE} found in Baseline but not in Comparison{Fore.RESET}")
            else:
                differences.append(f"Key {Fore.GREEN}'{new_path}'{Fore.RED} found in Comparison but not in Baseline{Fore.RESET}")

    elif isinstance(json1, list) and isinstance(json2, list):
        len1 = len(json1)
        len2 = len(json2)
        for i in range(max(len1, len2)):
            new_path = f"{path}[{i}]"
            if i < len1 and i < len2:
                differences.extend(compare_json(json1[i], json2[i], new_path))
            elif i < len1:
                differences.append(f"Index {Fore.GREEN}'{new_path}'{Fore.BLUE} found in Baseline but not in Comparison{Fore.RESET}")
            else:
                differences.append(f"Index {Fore.GREEN}'{new_path}'{Fore.RED} found in Comparison but not in Baseline; ADDED{Fore.RESET}")

    else:
        if json1 != json2:
            differences.append(f"Value {Fore.RED}CHANGED{Fore.RESET} at '{path}': Baseline has {Fore.MAGENTA}'{json1}'{Fore.RESET} and Comparison has {Fore.MAGENTA}'{json2}'{Fore.RESET}")

    return differences

def open_file_picker(file_type):
    # Create the main window
    root = tk.Tk()
    root.title(f"File Picker - {file_type}")
    root.geometry("600x100")

    # Variable to store the selected folder path
    file_path = ""

    # Function to handle folder selection
    def select_file():
        nonlocal file_path
        file_path = tk.filedialog.askopenfilename(
            initialdir=".",  # Set to your preferred starting directory
            filetypes=(("SHED log files", "*.shed"), ("All files", "*.*")),
            title="Select a file")
        file_path = file_path if file_path else "No folder selected"
        root.destroy()  # Close the window only after retrieving the folder path

    # Add a button to open the folder picker dialog
    open_file_btn = ttk.Button(root, text="Select file", command=select_file)
    open_file_btn.pack(pady=20)

    # Start the GUI event loop
    root.mainloop()

    # Return the folder path
    return file_path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SHut Em Down (SHED) - Comparer")
    parser.add_argument('-1','--baseline', help='Pre-Engagement file [BASELINE]')
    parser.add_argument('-2','--comparison', help='Post-Engagement file [COMPARISON]')
    parser.add_argument('-C', '--cli', action='store_true', help='CLI only; disables GUI popups')      

    args = parser.parse_args()

    no_GUI = True if args.cli or import_failure else False
    if args.baseline == None or not os.path.exists(args.baseline):
        print(f"{Fore.RED}System requires a baseline file: ")
        if no_GUI:
            f1 = get_file()
        else:
            f1 = open_file_picker("Baseline")
    else:
        f1 = args.baseline    
    if args.comparison == None or not os.path.exists(args.comparison):
        print(f"{Fore.RED}System requires a comparison file: ")
        if no_GUI:
            f2 = get_file()
        else:
            f2 = open_file_picker("Comparison")
    else:
        f2 = args.comparison    
    
    # Load JSON files
    json1 = load_json(f1)
    json2 = load_json(f2)

    # Compare JSON files and print differences
    differences = compare_json(json1, json2)
    for difference in differences:
        print(difference)
