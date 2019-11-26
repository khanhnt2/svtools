#!/usr/bin/env python3
import socket
import threading
import sqlite3
import datetime
import logging


logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%H:%M:%S')
lock = threading.Lock()


def decrypt(c):
    t = b''
    for d in c:
        t += bytes([(d ^ 1)])
    return t


def recv(p):
    global submit_flag_conn
    global db
    global lock

    l = p.recv(1024)
    d = decrypt(l)
    if b'UITCTF' in d:
        logging.info("flag is " + ''.join(map(chr, d)))
        now = str(datetime.datetime.now())
        try:
            lock.acquire(True)
            db.execute("""INSERT INTO flags VALUES (?, ?, ?)""", (''.join(map(chr, d)), now, False))
            submit_flag_conn.send(d + b'\n')
        except sqlite3.IntegrityError:
            pass
        except Exception as e:
            logging.error('Send flag fail. %s' % e)
        finally:
            db.commit()
            lock.release()


db = sqlite3.connect('flags.db', check_same_thread=False)
db.execute('''CREATE TABLE IF NOT EXISTS flags (flag TEXT PRIMARY KEY NOT NULL, time DATATIME, submit BOOLEAN)''')
flag_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
flag_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
flag_server.bind(('0.0.0.0', 8089))
flag_server.listen(1)
logging.info('Wait client to connect...')
submit_flag_conn, a = flag_server.accept()

logging.info('Start bot server')
bot_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
bot_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
bot_server.bind(('0.0.0.0', 8080))
bot_server.listen(10)

while 1:
    try:
        c, a = bot_server.accept()
        logging.info('New connection')
        t = threading.Thread(target=recv, args=(c,))
        t.start()
    except KeyboardInterrupt:
        db.close()
        break
    except Exception as e:
        logging.error(e)
        pass
