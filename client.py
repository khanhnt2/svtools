import requests
import socket

HOST = '167.179.90.83'
PORT = 8089
URL = 'http://10.33.250.18:8080/submit_flag'
COOKIE = ''
HEADERS = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0',
           'cookie': COOKIE}


def readline(conn):
    line = ''
    while 1:
        char = conn.recv(1)
        line += chr(char[0])
        if char == b'\n':
            break
    return line


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

while True:
    flag = readline(s)
    print('********')
    print('Sending flag: ', flag)
    data = {'team_id': 2, 'token': 'wKiyz4fBYk7XuPHEhmDEtxtjHhKTQaHdknxzWVyqZ9y3TqvigR', 'flag': flag}
    rq = requests.post(URL, data=data, headers=HEADERS)
    print('Status code: ', rq.status_code)
