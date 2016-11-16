'''
This module contains methods for testing access using the http basic auth protocol
'''

import requests
from requests.auth import HTTPBasicAuth


def test_http(ip, port, credentials):
    success = []
    for login in credentials:
        password = credentials[login]
        print (login)
        try:
            res = requests.get('http://'+str(ip)+':'+str(port)+'/', auth=HTTPBasicAuth(login,password))
            if res.status_code == 200:
                success.append([login,password])
        except Exception as e:
            break
    return success
