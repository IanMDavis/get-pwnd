'''
This module contains methods for testing access using the http basic auth protocol
'''

from smb.SMBConnection import SMBConnection
from nmb import NetBIOS


def test_smb(ip, port, credentials):
    success = []
    nb = NetBIOS.NetBIOS(broadcast=False)
    try:
        # names = nb.queryIPForName(ip,139,timeout=10)
        # if names == None or names == []:
        #     name = ""
        # else:
        #     name = names[0]
        for login in credentials:
            password = credentials[login]
            conn = SMBConnection(login, password, "PwnieXpress", "")
            result = conn.connect(ip,port=port,timeout=30)
            if result:
                success.append([login,password])
                conn.close()
    except Exception as e:
        print(e)
    nb.close()
    return success