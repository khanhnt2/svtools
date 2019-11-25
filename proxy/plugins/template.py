import abc


class PluginBase(abc.ABC):
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


# Example plugin
# Must be inherited from PluginBase
# and implement all abstract methods
# proxy server will call ExamplePlugin
class ExamplePlugin(PluginBase):
    def new_connection(self, conn):
        pass

    def send_server(self, data, conn):
        return data

    def send_client(self, data, conn):
        return data

    def finish_connection(self, conn):
        pass
