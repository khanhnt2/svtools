import requests
import socket

HOST = '10.0.0.0'
PORT = 8089
URL = 'ahihi.com'
COOKIE = ''
HEADERS = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0',
           'cookie': COOKIE}


def readline(conn):
    line = ''
    while 1:
        char = conn.recv(1)
        line += char
        if char == '\n':
            break
    return line


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

while True:
    flag = readline(s)
    print('********')
    print('Sending flag: ', flag)
    rq = requests.post(URL, data=flag, headers=HEADERS)
    print('Status code: ', rq.status_code)
