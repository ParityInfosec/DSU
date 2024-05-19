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
apiKey = "ABCDE"

# Hosts file path
hostsFile = "C:\\Windows\\System32\\drivers\\etc\\hosts"

# Stop event for threads
stop_event = threading.Event()

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

def start_proxy():
    subprocess.run(["netsh", "interface", "portproxy", "add", "v4tov4", "listenport=80", "listenaddress=127.0.0.1", "connectport=8080", "connectaddress=127.0.0.1"])
    subprocess.run(["netsh", "interface", "portproxy", "add", "v4tov4", "listenport=443", "listenaddress=127.0.0.1", "connectport=8081", "connectaddress=127.0.0.1"])

def stop_proxy():
    subprocess.run(["netsh", "interface", "portproxy", "delete", "v4tov4", "listenport=80", "listenaddress=127.0.0.1"])
    subprocess.run(["netsh", "interface", "portproxy", "delete", "v4tov4", "listenport=443", "listenaddress=127.0.0.1"])

def convert_to_base64_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def check_site(url):
    base64dom = convert_to_base64_url(url)
    headers = {"accept": "application/json", "x-apikey": apiKey}
    response = requests.get(f'https://www.virustotal.com/api/v3/urls/{base64dom}/votes?limit=10', headers=headers)
    return response.json()

def show_options_box(message):
    root = Tk()
    root.withdraw()  # Hide the root window
    result = messagebox.askyesno("Redirect Link Alert", f"{message}\n\nDo you want to continue?")
    root.destroy()
    return result

class RequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        protocol = 'https' if self.server.server_port ==8081 else 'http'
        host = self.headers.get('Host')
        original_url = (f"{protocol}://{host}{self.path}")
        clean_hosts(host)
        expanded_url = expand_url(original_url)
        load_hosts(shortURLs)
        print(expanded_url)
        if expanded_url:
            output = check_site(expanded_url)
            options_choice = show_options_box(output)

            if options_choice:
                self.send_response(302)
                self.send_header('Location', expanded_url)
                self.end_headers()
            else:
                self.send_response(403)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(f"Access denied: The requested URL ({expanded_url}) is considered malicious.".encode('utf-8'))
        else:
            self.send_response(500)
            self.end_headers()

class HTTPRequestHandler(RequestHandler):
    pass

class HTTPSRequestHandler(RequestHandler):
    pass

def start_http_server():
    httpd = http.server.HTTPServer(('127.0.0.1', 8080), HTTPRequestHandler)
    print("HTTP Server running on http://127.0.0.1:8080")
    while not stop_event.is_set():
        httpd.handle_request()
    httpd.server_close()

def start_https_server():
    httpd = http.server.HTTPServer(('127.0.0.1', 8081), HTTPSRequestHandler)

    # Create SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    certpath = path + '\certificate.pem'
    keypath = path + '\privkey.pem'
    context.load_cert_chain(certfile=certpath, keyfile=keypath)

    # Wrap the socket
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print("HTTPS Server running on https://127.0.0.1:8081")
    while not stop_event.is_set():
        httpd.handle_request()
    httpd.server_close()

def load_hosts(urls):
    with open(hostsFile, 'a+') as file:
        file.seek(0)
        lines = file.readlines()
        for url in urls:
            entry = f"127.0.0.1 {url}\n"
            if entry not in lines:
                file.write(entry)

def clean_hosts(urls):
    with open(hostsFile, 'r') as file:
        lines = file.readlines()
    with open(hostsFile, 'w') as file:
        for line in lines:
            if not any(url in line for url in urls):
                file.write(line)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="URL Expander Script")
    parser.add_argument('--api_key', required=True, help='VirusTotal API Key')
    args = parser.parse_args()
    apiKey = args.api_key
    print(apiKey)

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
    except KeyboardInterrupt:
        print("Stopping the script...")
        stop_event.set()
        http_thread.join()
        https_thread.join()
        print("Threads joined...Cleaning Hosts file")
        clean_hosts(shortURLs)
        stop_proxy()
    finally:
        stop_event.set()
        http_thread.join()
        https_thread.join()
        clean_hosts(shortURLs)
        stop_proxy()