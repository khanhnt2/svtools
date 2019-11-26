import requests
import socket

HOST = '167.179.90.83'
PORT = 8089
URL = 'http://192.168.3.145/submitter/submitflag.php'
COOKIE = ''
HEADERS = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0',
           'cookie': COOKIE}


def readline(conn):
    line = ''
    while 1:
        char = conn.recv(1)
        if char == b'\n':
            break
        line += chr(char[0])
    return line


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

while True:
    message = readline(s).split('|')
    flag = message[0]
    host = '0.0.0.0'
    port = '0000'
    if len(message) >= 3:
        host = message[1]
        port = message[2]
    print('********')
    print('Sending flag: ', flag)
    data = {'host': host, 'port': port, 'flag': flag}
    rq = requests.get(URL, params=data, headers=HEADERS)
    print('Status code: ', rq.status_code, rq.text)
