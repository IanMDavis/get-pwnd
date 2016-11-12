"""
This module contains methods for testing access using the telnet and ssh protocols.

The original intention was to use Hydra for both, but after extensive testing, it
makes too many attempts to access a service and takes too long:
hydra -F -l login -p password -t 1 telnet://localhost:23

As a result, the Hydra interface turned into separate implementations of ssh and 
telnet protocols.

http://tools.kali.org/password-attacks/hydra
"""

import telnetlib
from pexpect import pxssh

def test_telnet(ip, port, credentials):
    for login in credentials:
        try:
            tn = telnetlib.Telnet(ip, port)
        except:
            break

        password = credentials[login]
        tn.read_until(b"login: ")
        tn.write(login.encode('ascii') + b"\n")

        read_str = tn.read_until(b"Password:", timeout=1)
        # The string appeared, no timeout.
        if b"Password:" in read_str:
            # In case there is a space after "Password:".
            tn.read_eager()
            tn.write(password.encode('ascii') + b"\n")

            read_str = tn.read_until(b"login:")
            guessed_password = password
        else:
            # If login was successful without a password, read_str will contain "Last login".
            read_str = tn.read_eager()
            guessed_password = ""
        tn.close()

        if b"Last login" in read_str:
            return (login, guessed_password)
    return None

def test_ssh(ip, port, credentials):
    for login in credentials:
        password = credentials[login]
        ssh = pxssh.pxssh()
        try:
            ssh.login(ip, login, password)
        except pxssh.ExceptionPxssh:
            continue
        ssh.logout()
        return (login, password)
    return None
