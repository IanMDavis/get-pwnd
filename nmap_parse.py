"""
This module is responsible for interaction with the nmap tool.
"""
import nmap
# EDIT THIS IF YOU ADD ANOTHER SERVICE!!!!!
services = ["telnet", "ssh", "http", "websocket", "smb", "microsoft-ds", "https"]

def scan(targets_range, all_ports, ports):
    """
    Scans the specified IP / IP range using nmap, returns a dict of discovered ports

    Args:
        targets_range (string): description
            Target range to scan. For the current implementation, This
            argument must contain a single IP address to test against.

    Returns:
        Dict containing discovered services in the following format:
        {
            {'192.168.1.1': {'ssh': 22, 'telnet': 23}},
            {'192.168.1.2': {'smtp': 25}}
        }
    """
    targets_dict = {}
    targets = targets_range.split(",")
    for target in targets:
        nm = nmap.PortScanner()
        if all_ports:
            nm.scan(hosts=target, arguments='-sV -Pn -p-')
        elif ports:
            args = '-sV -Pn -p' + ports
            nm.scan(hosts=target, arguments=args)
        else:
            nm.scan(hosts=target, arguments='-sV -Pn')
        for host in nm.all_hosts():
            host_object = {}
            for protocol in nm[host].all_protocols():
                for port in nm[host][protocol].keys():
                    info = nm[host][protocol][port]
                    if (info['name'] in services and info['state'] == 'open'):
                        host_object[info['name']] = port
            targets_dict[host] = host_object

    return targets_dict
