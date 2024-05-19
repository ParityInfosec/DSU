import os
import sys
import base64
import requests
import threading
import http.server
import ssl
from urllib.parse import urlparse
from tkinter import Tk, messagebox

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
hostsFile = "/etc/hosts"  # Adjust this path for Windows: "C:\\Windows\\System32\\drivers\\etc\\hosts"

def expand_url(url):
    try:
        response = requests.head(url, allow_redirects=True)
        return response.url
    except requests.RequestException as e:
        print(f"Error expanding URL: {e}")
        return None

def start_proxy():
    os.system("sudo iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8080")
    os.system("sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8081")

def stop_proxy():
    os.system("sudo iptables -t nat -D OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8080")
    os.system("sudo iptables -t nat -D OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8081")

def convert_to_base64_url(url):
    url_bytes = url.encode('utf-8')
    base64_bytes = base64.urlsafe_b64encode(url_bytes)
    return base64_bytes.decode('utf-8').rstrip('=')

def check_site(url):
    base64dom = convert_to_base64_url(url)
    headers = {"accept": "application/json", "x-apikey": apiKey}
    response = requests.get(f'https://www.virustotal.com/api/v3/domains/{base64dom}', headers=headers)
    return response.json()

def show_options_box(message):
    root = Tk()
    root.withdraw()  # Hide the root window
    result = messagebox.askyesno("Redirect Link Alert", f"{message}\n\nDo you want to continue?")
    root.destroy()
    return result

class RequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        original_url = self.path[1:]  # Remove leading '/'
        expanded_url = expand_url(original_url)
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

def start_server():
    httpd = http.server.HTTPServer(('127.0.0.1', 8080), RequestHandler)
    httpd.socket = ssl.wrap_socket(httpd.socket, certfile='/path/to/certfile.pem', server_side=True)  # Adjust certfile path
    httpd.serve_forever()

def load_hosts():
    with open(hostsFile, 'a+') as file:
        file.seek(0)
        lines = file.readlines()
        for shortURL in shortURLs:
            entry = f"127.0.0.1 {shortURL}\n"
            if entry not in lines:
                file.write(entry)

def clean_hosts():
    with open(hostsFile, 'r') as file:
        lines = file.readlines()
    with open(hostsFile, 'w') as file:
        for line in lines:
            if not any(shortURL in line for shortURL in shortURLs):
                file.write(line)

if __name__ == "__main__":
    try:
        print("Press Ctrl+C to stop the script...")
        load_hosts()
        start_proxy()
        threading.Thread(target=start_server).start()
        while True:
            pass
    except KeyboardInterrupt:
        print("Stopping the script...")
        clean_hosts()
        stop_proxy()
    finally:
        clean_hosts()
        stop_proxy()
