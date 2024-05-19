import os
import ssl
import http.server
import threading
import requests
import subprocess
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

def expand_url(url):
    try:
        response = requests.head(url, allow_redirects=True)
        return response.url
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

class HTTPRequestHandler(RequestHandler):
    pass

class HTTPSRequestHandler(RequestHandler):
    pass

def start_http_server():
    httpd = http.server.HTTPServer(('127.0.0.1', 8080), HTTPRequestHandler)
    print("HTTP Server running on http://127.0.0.1:8080")
    httpd.serve_forever()

def start_https_server():
    httpd = http.server.HTTPServer(('127.0.0.1', 8081), HTTPSRequestHandler)

    # Create SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=os.path.join(path, 'certificate.pem'), keyfile=os.path.join(path, 'privatekey.pem'))

    # Wrap the socket
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print("HTTPS Server running on https://127.0.0.1:8081")
    httpd.serve_forever()

def load_hosts():
    with open(hostsFile, 'a+') as file:
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
        threading.Thread(target=start_http_server).start()
        threading.Thread(target=start_https_server).start()
        while True:
            pass
    except KeyboardInterrupt:
        print("Stopping the script...")
    finally:
        clean_hosts()
        stop_proxy()
