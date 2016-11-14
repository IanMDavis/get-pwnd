'''
This module contains methods for testing access using the telnet protocol
'''

import telnetlib

def test_telnet(ip, port, credentials):
    success = []
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
            #Append to keep track of multiple successes
            success.append([login,password])
    return success