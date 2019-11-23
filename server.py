import socket, threading


def decrypt(c):
	t = b''
	for d in c:
		t += bytes([(d^1)])
	return t

def recv(p):
	l = p.recv(1024)
	d = decrypt(l)
	print("flag is",d)

s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

s.bind(('0.0.0.0',8080))
s.listen(10)
while 1:
	try:
		c, a = s.accept()
		threading.Thread(target = recv(c))
	except KeyboardInterrupt:
		break
	except Exception as e:
		print(e)
		pass

