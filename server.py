#!/usr/bin/env python3
import socket
import threading


def decrypt(c):
    t = b''
    for d in c:
        t += bytes([(d ^ 1)])
    return t


def recv(p):
    global submit_flag_conn

    l = p.recv(1024)
    d = decrypt(l)
    if b'UITCTF' in d:
        print("flag is", d)
    submit_flag_conn.send(d + '\n')


flag_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
flag_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
flag_server.bind(('0.0.0.0', 8089))
flag_server.listen(1)
print('Wait client to connect...')
submit_flag_conn, a = flag_server.accept()

print('Start bot server')
bot_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
bot_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
bot_server.bind(('0.0.0.0', 8080))
bot_server.listen(10)

while 1:
    try:
        c, a = bot_server.accept()
        print('New connection')
        threading.Thread(target=recv(c))
    except KeyboardInterrupt:
        break
    except Exception as e:
        print(e)
        pass
