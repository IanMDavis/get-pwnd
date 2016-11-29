"""
This tool accepts a file containing IP addresses or nmap-suitable address ranges, 
usernames and passwords, and does the following:

1) Scans the provided IP range with nmap.
2) Tries to gain access to as many services as it can using different tools
   for every result from the previous step.

Usage:
    python3 getpwnd.py -f config/scan-config.txt -p port#,port#
"""

import sys
import nmap_parse as nmap
import jobs
import modules.ssh as ssh
import modules.telnet as telnet
import modules.http as http
import modules.https as https
import modules.smb as smb
import argparse
from colorama import Fore, Back, Style

def main():

    parser = argparse.ArgumentParser(description='Get Pwnd - Verify system credentials')
    parser.add_argument('-f', required=True, metavar='--file', help='Required configuration file.')
    parser.add_argument('-a', action='store_true', help='Scan all ports on all systems')
    parser.add_argument('-p', metavar='--ports', help='List of comma separated ports (ex: -p 22,23)')

    args = parser.parse_args()

    print(Fore.RED + """
         _____      _    ______                    _ 
        |  __ \    | |   | ___ \                  | |
        | |  \/ ___| |_  | |_/ /_      ___ __   __| |
        | | __ / _ \ __| |  __/\ \ /\ / / '_ \ / _` |
        | |_\ \  __/ |_  | |    \ V  V /| | | | (_| |
         \____/\___|\__| \_|     \_/\_/ |_| |_|\__,_|
         - Verify system credentials
        """ + Style.RESET_ALL)

    all_ports = False
    if args.a:
        all_ports = True
        print("!!! Scanning all 65535 ports. This will take some time. !!!")
    ports = None
    if args.p:
        ports = args.p

    parsed_config = parse_config_file(args.f)
    print("Finding online systems...")
    print("Finding open ports...")
    services_by_ip = nmap.scan(parsed_config['targets'], all_ports, ports)
    credentials = parsed_config['credentials']
    
    print("Verifying credentials...")
    dispatcher = jobs.Dispatcher()
    dispatcher.add_tester('ssh', ssh.test_ssh)
    dispatcher.add_tester('telnet', telnet.test_telnet)
    dispatcher.add_tester('http', http.test_http)
    dispatcher.add_tester('websocket', http.test_http)
    dispatcher.add_tester('smb', smb.test_smb)
    dispatcher.add_tester('microsoft-ds', smb.test_smb)
    dispatcher.add_tester('https', https.test_https)
    #Add more services here

    results_by_ip = dispatcher.run(services_by_ip, credentials)

    
    #Success count
    count = 0
    results_by_ip = format_results(results_by_ip)
    success = list()
    print("Found matches:")
    for ip in results_by_ip:
        print("\tIP: %s" % (ip))
        creds_by_service = results_by_ip[ip]
        for service in creds_by_service:
            #Each successful login per service per IP
            #(Fix for original bug where only one cred would be shown as success)
            for entry in creds_by_service[service]:
                (port, login, password) = entry
                print(Fore.GREEN + "\t\tService: %s\tPort: %s\tUsername: %s\tPassword: %s" % (service, port, login, password) + Style.RESET_ALL)
                count += 1

    if count == 0:
        print(Fore.RED + "\tNo valid credentials found." + Style.RESET_ALL)
        return

def parse_config_file(filename):
    """
    Parses scan config file and retrieves all login:password pairs
    as well as targets_range.
    """
    creds_map = {}
    targets_range = ""
    file_pointer = open(filename, "r")
    for i, line in enumerate(file_pointer):
        if i == 0:
            targets_range = line.rstrip('\n')
            continue
        # t[0] - username
        # t[1] - password
        tmp = line.rstrip('\n').split(":", 1)
        # In case there are invalid credentials.
        if len(tmp) != 2:
            print(Back.RED + "Invalid credentials format: %s, must be login:password" % (line.strip()) + Style.RESET_ALL)
            continue
        # NOTE: If there are several identical logins, only the last will be written.
        creds_map[tmp[0]] = tmp[1]
    file_pointer.close()
    return {"targets": targets_range, "credentials": creds_map}

# Running the script from the command line.

def format_results(ip_results):
    max_service = max_port = max_username = max_password = 0
    for ip in ip_results:
        for service in ip_results[ip]:
            for entry in ip_results[ip][service]:
                (port, login, password) = entry
                max_service = max(len(service), max_service)
                max_port = max(len(str(port)), max_port)
                max_username = max(len(login), max_username)
                max_password = max(len(password), max_password)
    
    for ip in ip_results:
        ip_stuff={}
        for service in ip_results[ip]:
            service_results = []
            for entry in ip_results[ip][service]:
                (port, login, password) = entry
                if (len(service) < max_service):
                    service = service + (max_service - len(service))*" " 
                if (len(str(port)) < max_port):
                    port = str(port) + (max_port - len(str(port)))*" "
                if (len(login) < max_username):
                    login = login + (max_username - len(login))*" "
                if (len(password) < max_password):
                    password = password + (max_password - len(password))*" "
                service_results.append((port,login,password))
            ip_stuff[service] = service_results
        ip_results[ip] = ip_stuff

    return ip_results

if __name__ == "__main__":
    main()
