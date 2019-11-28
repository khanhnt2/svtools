from base import PluginBase
from graylog import Graylog
import os


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


class LogGraylog(PluginBase):
    '''Send to graylog server'''
    def __init__(self):
        self.enable = True
        self.graylog = Graylog()

    def new_connection(self, conn):
        pass

    def send_client(self, data, conn):
        self.graylog.log_data(data, conn, 'server')
        return data

    def send_server(self, data, conn):
        self.graylog.log_data(data, conn, 'client')
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

    def finish_connection(self, conn):
        pass
