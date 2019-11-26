from base import PluginBase
import os


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
