'''
This module contains methods for testing access using the http basic auth protocol
'''

from smb.SMBConnection import SMBConnection
from nmb import NetBIOS


def test_smb(ip, port, credentials):
    success = []
    for login in credentials:
        password = credentials[login]
        nb = NetBIOS.NetBIOS(broadcast=False)
        try:
            names = nb.queryIPForName(ip,port,timeout=1)
            if names == None or names == []:
                break
            name = names[0]
            conn = SMBConnection(login, password, "PwnieXpress", name)
            if conn.connect(ip,port=port,timeout=1):
                success.append([login,password])
                conn.close()
        except Exception as e:
            print(e)
            break
        nb.close()
    return success