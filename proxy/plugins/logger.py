from base import PluginBase
import os
import requests
import base64
import threading
import logging


class LogConsole(PluginBase):
    def __init__(self):
        self.enable = False

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
    def __init__(self):
        self.enable = False

    def new_connection(self, conn):
        # Create new file
        path_client = os.path.join(conn.app_name, str(conn.id) + '_client.log')
        path_server = os.path.join(conn.app_name, str(conn.id) + '_server.log')
        open(path_client, 'wb').write(b'')
        open(path_server, 'wb').write(b'')

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


class GrayLog(PluginBase):
    '''Send to graylog server'''
    def __init__(self):
        self.enable = True

    def thread_func(self, data, conn, who_send):
        _data = str(data)
        header = {'Content-Type': 'application/json'}
        pdata = {"version": "1.1", "host": conn.app_name, 'short_message': _data, "level": 5, 'conn_id': conn.id, 'datetime': conn.datetime, 'who_send': who_send}
        try:
            requests.post('http://192.168.56.117:12201/gelf', json=pdata, headers=header, timeout=2.0)
        except Exception as e:
            logging.error('Send graylog: ' + str(e))

    def new_connection(self, conn):
        pass

    def send_client(self, data, conn):
        t = threading.Thread(target=self.thread_func, args=(data, conn, 'server',))
        t.start()
        return data

    def send_server(self, data, conn):
        t = threading.Thread(target=self.thread_func, args=(data, conn, 'client',))
        t.start()
        return data

    def finish_connection(self, conn):
        pass


class LogTcpStream(PluginBase):
    '''Log TCP stream, userful for binary challenges'''
    def __init__(self):
        self.enable = False

    def new_connection(self, conn):
        # Create new file
        path = os.path.join(conn.app_name, str(conn.id) + '_tcpstream.log')
        open(path, 'wb').write(b'')

    def send_server(self, data, conn):
        path = os.path.join(conn.app_name, str(conn.id) + '_tcpstream.log')
        open(path, 'ab').write(data)
        return data

    def send_client(self, data, conn):
        path = os.path.join(conn.app_name, str(conn.id) + '_tcpstream.log')
        open(path, 'ab').write(data)
        return data

    def thread_func(self, conn, who_send):
        path = os.path.join(conn.app_name, str(conn.id) + '_tcpstream.log')
        data = open(path, 'rb').read()
        _data = str(data)
        header = {'Content-Type': 'application/json'}
        pdata = {"version": "1.1", "host": conn.app_name, "short_message": "1233", 'ahihi_message': _data, "level": 5, 'conn_id': conn.id, 'datetime': conn.datetime, 'who_send': who_send}
        # pdata = {"version": "1.1", "host": conn.app_name, "short_message": "A short message", "level": 5, "_some_info": "foo"}
        try:
            requests.post('http://192.168.56.117:12201/gelf', json=pdata, headers=header, timeout=2.0)
        except Exception as e:
            logging.error('Send graylog: ' + str(e))

    def finish_connection(self, conn):
        t = threading.Thread(target=self.thread_func, args=(conn, 'client',))
        t.start()
        pass
