'''
Copyright (c) 2024 Justin Cornwell justin.cornwell@trojans.dsu.edu

Created Date: Saturday, May 18th 2024, 5:02:36 pm
Author: Justin Cornwell
----------------
Course: CSC842
Project/Lab: Cycle 1 - Extend-Check (Windows)
----------	---	----------------------------------------------------------
'''

import os
import ssl
import http.server
import threading
import requests
import subprocess
import base64
import argparse
from urllib.parse import urlparse
from tkinter import Tk, messagebox

# Easier to run outside current directory
path = os.path.abspath(os.path.dirname(__file__))

# Define known short URL services
shortURLs = [
    "3.ly", "bit.ly", "bitly.kr", "bl.ink", "buff.ly", "clicky.me", "cutt.ly", "Dub.co", "fox.ly", "gg.gg", "han.gl", 
    "hoy.kr", "is.gd", "KurzeLinks.de", "kutt.it", "LinkHuddle.com", "LinkSplit.io", "lstu.fr", "name.com", "oe.cd", 
    "Ow.ly", "rebrandly.com", "rip.to", "san.aq", "short.io", "shorturl.at", "smallseotools.com", "spoo.me", 
    "switchy.io", "t.co", "T2M.co", "tinu.be", "TinyURL.com", "T.LY", "urlr.me", "v.gd", "vo.la"
]

# VirusTotal API Key
apiKey = "ABCDE"        # Never hard code; mandatory argument on start

# Hosts file path
hostsFile = "C:\\Windows\\System32\\drivers\\etc\\hosts"

# Stop event for threads; graceful close
stop_event = threading.Event()

# Find redirect message to extract actual target
def expand_url(url):
    try:
        print(f"Expanding...{url}")
        response = requests.get(url, allow_redirects=False, timeout=10)
        if response.status_code in (301, 302, 303, 307, 308) and 'Location' in response.headers:
            url = response.headers['Location']
            print(f"Expanded...{url}")
        return url
    except requests.RequestException as e:
        print(f"Error expanding URL: {e}")
        return None

# Forward 80/443 to 8080/8081
def start_proxy():
    subprocess.run(["netsh", "interface", "portproxy", "add", "v4tov4", "listenport=80", "listenaddress=127.0.0.1", "connectport=8080", "connectaddress=127.0.0.1"])
    subprocess.run(["netsh", "interface", "portproxy", "add", "v4tov4", "listenport=443", "listenaddress=127.0.0.1", "connectport=8081", "connectaddress=127.0.0.1"])

# Stop forwarding
def stop_proxy():
    subprocess.run(["netsh", "interface", "portproxy", "delete", "v4tov4", "listenport=80", "listenaddress=127.0.0.1"])
    subprocess.run(["netsh", "interface", "portproxy", "delete", "v4tov4", "listenport=443", "listenaddress=127.0.0.1"])

# API to VirusTotal for site check
def check_site(url):
    print(url)
    headers = {"accept": "application/json", "x-apikey": apiKey}
    response = requests.get(f'https://www.virustotal.com/api/v3/domains/{url}/votes', headers=headers)
    return response.text

# Display links & site check results
def show_options_box(url, expanded_url, message):
    root = Tk()
    root.withdraw()  # Hide the root window
    root.attributes("-topmost", True)  # Make sure the root window is on top
    root.update()  # Update the window to ensure it processes the above changes

    result = messagebox.askyesno("Redirect Link Alert", f"Original Link: {url}\n\nDid you intend to go to {expanded_url}\n\n\{message}\n\nDo you want to continue?")
    root.destroy()
    return result       # Use results to determine if traffic passes

# HTTP(S) handler guiding checks
class RequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        protocol = 'https' if self.server.server_port ==8081 else 'http'        # Determine HTTP/HTTPS
        host = self.headers.get('Host')                                         # Isolate domain
        original_url = (f"{protocol}://{host}{self.path}")                      # Rebuild original link
        clean_hosts(host)                                                       # Unblock link long enough to expand url
        expanded_url = expand_url(original_url)                                 # Deobfuscate shortened link
        load_hosts(shortURLs)                                                   # Reblock site
        print(expanded_url)
        # If link can be deobfuscated...
        if expanded_url:
            output = check_site(urlparse(expanded_url).hostname)                            # Query VirusTotal
            options_choice = show_options_box(original_url, expanded_url, output)           # Display Continue/Quit box with VirusTotal info

            if options_choice:                                  # If Yes, continue
                self.send_response(302)
                self.send_header('Location', expanded_url)
                self.end_headers()
            else:                                               # If No, send denial message
                self.send_response(403)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(f"Access denied: The requested URL ({expanded_url}) is potentially malicious.".encode('utf-8'))
        else:                                                   # If link can't be deobfuscated
            self.send_response(500)
            self.end_headers()

class HTTPRequestHandler(RequestHandler):
    pass

class HTTPSRequestHandler(RequestHandler):
    pass

# Build HTTP Listener
def start_http_server():
    httpd = http.server.HTTPServer(('127.0.0.1', 8080), HTTPRequestHandler)
    print("HTTP Server running on http://127.0.0.1:8080")
    while not stop_event.is_set():
        httpd.handle_request()                                      # Graceful Close
    httpd.server_close()

# Build HTTPS Listener
def start_https_server():
    httpd = http.server.HTTPServer(('127.0.0.1', 8081), HTTPSRequestHandler)

    # Create SSL context with pre-made keys (default included in git pkg)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    certpath = path + '\certificate.pem'                            # Certs in same folder
    keypath = path + '\privkey.pem'                                 # Private Key in same folder; generate and maintain locally
    context.load_cert_chain(certfile=certpath, keyfile=keypath)

    # Wrap the socket
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print("HTTPS Server running on https://127.0.0.1:8081")
    while not stop_event.is_set():                                  # Graceful Close
        httpd.handle_request()
    httpd.server_close()

# "Blackhole" URL shorteners to localhost in .../etc/hosts
def load_hosts(urls):
    with open(hostsFile, 'a+') as file:
        file.seek(0)
        lines = file.readlines()                                       # Read hosts file
        for url in urls:
            entry = f"127.0.0.1 {url}\n"                               # Build hosts lines
            if entry not in lines:                                      
                file.write(entry)                                      # Check if url is in hosts file; if not, write entry to hosts

# Remove URL shortners from .../etc/hosts; can be full list or individual sites (for "unblocking")
def clean_hosts(urls):
    with open(hostsFile, 'r') as file:
        lines = file.readlines()                                       # Read hosts file
    with open(hostsFile, 'w') as file:
        for line in lines:
            if not any(url in line for url in urls):                   # If content is not a url in array, write to file; deletes added references
                file.write(line)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="URL Expander Script")
    parser.add_argument('--api_key', required=True, help='VirusTotal API Key')              # Force API key argument for VirusTotal
    args = parser.parse_args()
    apiKey = args.api_key

    try:
        print("Press Ctrl+C to stop the script...")
        load_hosts(shortURLs)
        start_proxy()
        http_thread = threading.Thread(target=start_http_server, daemon=True)
        https_thread = threading.Thread(target=start_https_server, daemon=True)
        http_thread.start()
        https_thread.start()
        while http_thread.is_alive() or https_thread.is_alive():
            http_thread.join(1)
            https_thread.join(1)
    except KeyboardInterrupt:                                                               # Ctrl-C interrupts and shuts down tool
        print("Stopping the script...")
        stop_event.set()                                                                    # Signal stop to thread loops
        http_thread.join()
        https_thread.join()
        print("Threads joined...Cleaning Hosts file")   
        clean_hosts(shortURLs)
        stop_proxy()
    finally:                                                                                   # Ensure cleanup if error not caught
        stop_event.set()
        http_thread.join()
        https_thread.join()
        clean_hosts(shortURLs)
        stop_proxy()