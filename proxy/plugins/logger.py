from plugins.template import PluginBase


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
