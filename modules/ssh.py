'''
This module contains methods for testing access using the ssh protocol.
'''

from pexpect import pxssh

def test_ssh(ip, port, credentials):
    success = []
    for login in credentials:
        password = credentials[login]
        ssh = pxssh.pxssh()
        try:
            ssh.login(ip, login, password, port=port)
        except pxssh.ExceptionPxssh:
            continue
        ssh.logout()

        #Append rather than return to allow for multiple successes
        success.append([login,password])
    return success
