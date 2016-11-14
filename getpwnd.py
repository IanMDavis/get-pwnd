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
import nmap
import jobs
import modules.ssh as ssh
import modules.telnet as telnet

def main():
    if len(sys.argv) < 2:
        exit("Usage:\n\tpython3 getpwnd.py <scan_config_file>")

    parsed_config = parse_config_file(sys.argv[1])
    services_by_ip = nmap.scan(parsed_config['targets'])
    credentials = parsed_config['credentials']

    dispatcher = jobs.Dispatcher()
    dispatcher.add_tester('ssh', ssh.test_ssh)
    dispatcher.add_tester('telnet', telnet.test_telnet)
    #Add more services here

    results_by_ip = dispatcher.run(services_by_ip, credentials)

    #Success count
    count = 0

    for ip in results_by_ip:
        creds_by_service = results_by_ip[ip]
        for service in creds_by_service:
            #Each successful login per service per IP
            #(Fix for original bug where only one cred would be shown as success)
            for entry in creds_by_service[service]:
                (port, login, password) = entry
                print("\n \"%s\" + \"%s\" was successful on host %s running %s (port %s)" %
                    (login, password, ip, service, port))
                count += 1

    if count == 0:
        print("No matches found.")
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
