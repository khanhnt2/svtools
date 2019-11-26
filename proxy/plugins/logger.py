from base import PluginBase
import os
import requests
import base64
import threading


class LogConsole(PluginBase):
    def new_connection(self, conn):
        pass

    def send_server(self, data, conn):
        print('******* Connection %d - Client send *******' % conn.id)
        print(data)
        print('******************************************')
        print()
        return data

    def send_client(self, data, conn):
        print('******* Connection %d - Server send *******' % conn.id)
        print(data)
        print('******************************************')
        print()
        return data

    def finish_connection(self, conn):
        pass


class LogFile(PluginBase):
    def new_connection(self, conn):
        pass

    def send_server(self, data, conn):
        path = os.path.join(conn.app_name, str(conn.id) + '_client.log')
        open(path, 'ab').write(data)
        return data

    def send_client(self, data, conn):
        path = os.path.join(conn.app_name, str(conn.id) + '_server.log')
        open(path, 'ab').write(data)
        return data

    def finish_connection(self, conn):
        pass


class LogServer(PluginBase):
    def __init__(self):
        super().__init__()
        self.url = 'http://192.168.3.145/writelog.php'

    def thread_logserver(self, _data, conn, who_send):
        buffer = _data
        if who_send == 'client':
            buffer += conn.buffer_client
        else:
            buffer += conn.buffer_server
        data = {'who_send': who_send, 'rule_name': self.__class__.__name__, 'id': conn.id, 'time': conn.datetime, 'app_name': conn.app_name, 'data': base64.b64encode(buffer)}
        rq = requests.post(self.url, data=data)
        print('Send data ' + who_send + ': ' + rq.text)

    def new_connection(self, conn):
        pass

    def send_server(self, data, conn):
        t = threading.Thread(target=self.thread_logserver, args=(data, conn, 'client',))
        t.start()
        return data

    def send_client(self, data, conn):
        t = threading.Thread(target=self.thread_logserver, args=(data, conn, 'server',))
        t.start()
        return data

    def finish_connection(self, conn):
        pass
