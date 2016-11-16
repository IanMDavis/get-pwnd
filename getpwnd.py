"""
This tool accepts a file containing IP addresses or nmap-suitable address ranges, 
usernames and passwords, and does the following:

1) Scans the provided IP range with nmap.
2) Tries to gain access to as many services as it can using different tools
   for every result from the previous step.

Usage:
    python3 getpwnd.py <scan_config_file>

This code is a placeholder / proof of concept until Ian writes real main.
"""

import sys
import nmap_parse as nmap
import jobs
import modules.ssh as ssh
import modules.telnet as telnet
import argparse

def main():

    parser = argparse.ArgumentParser(description='Get Pwnd - Verify system credentials')
    parser.add_argument('-f', required=True, metavar='--file', help='Required configuration file.')
    parser.add_argument('-a', action='store_true', help='Scan all ports on all systems')
    parser.add_argument('-p', metavar='--ports', help='Give csv for desired ports to be scanned')

    args = parser.parse_args()

    print("""
         _____      _    ______                    _ 
        |  __ \    | |   | ___ \                  | |
        | |  \/ ___| |_  | |_/ /_      ___ __   __| |
        | | __ / _ \ __| |  __/\ \ /\ / / '_ \ / _` |
        | |_\ \  __/ |_  | |    \ V  V /| | | | (_| |
         \____/\___|\__| \_|     \_/\_/ |_| |_|\__,_|
         - Verify system credentials
        """)

    all_ports = False
    if args.a:
        all_ports = True
        print("!!! Scanning all 65535 ports. This will take some time. !!!")

    parsed_config = parse_config_file(args.f)
    print("Finding online systems...")
    print("Finding open ports...")
    services_by_ip = nmap.scan(parsed_config['targets'], all_ports, args.p)
    credentials = parsed_config['credentials']

    print("Verifying credentials...")
    dispatcher = jobs.Dispatcher()
    dispatcher.add_tester('ssh', ssh.test_ssh)
    dispatcher.add_tester('telnet', telnet.test_telnet)
    #Add more services here

    results_by_ip = dispatcher.run(services_by_ip, credentials)

    
    #Success count
    count = 0

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
                print("\t\tProtocol: %s\tPort: %s\tUsername: %s\tPassword: %s" % (service, port, login, password))
                # print("\n \"%s\" + \"%s\" was successful on host %s running %s (port %s)" %
                #    (login, password, ip, service, port))
                count += 1

    if count == 0:
        print("\tNo valid credentials found.")
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
            print("Invalid credentials format: %s, must be login:password" % (line))
            continue
        # NOTE: If there are several identical logins, only the last will be written.
        creds_map[tmp[0]] = tmp[1]
    file_pointer.close()
    return {"targets": targets_range, "credentials": creds_map}

# Running the script from the command line.

if __name__ == "__main__":
    main()
