"""
This module is responsible for interaction with the nmap tool. This is a placeholder
with hardcoded ports until nmap scan / nmap results parsing is implemented.
"""

def scan(targets_range):
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
    # TODO: Do real scanning and parse results (Nick).
    return {
        targets_range: {'ssh': 22, 'telnet': 23},
    }
