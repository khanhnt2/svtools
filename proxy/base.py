import abc


class PluginBase(abc.ABC):
    # priority to call plugin, lower first
    priority = 999
    # enable plugin after load
    enable = True

    @abc.abstractmethod
    def new_connection(self, conn):
        '''Will be called when have a new connection'''
        pass

    @abc.abstractmethod
    def send_server(self, data, conn) -> bytes:
        '''Will be called when send data to server'''
        return data

    @abc.abstractmethod
    def send_client(self, data, conn) -> bytes:
        '''Will be called when send data to client'''
        return data

    @abc.abstractmethod
    def finish_connection(self, conn):
        '''Will be called when connection close'''
        pass

    def drop_connection(self, conn):
        conn.client.close()
        conn.server.close()
