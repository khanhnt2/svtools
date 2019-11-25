import abc


class PluginBase(abc.ABC):
    @abc.abstractmethod
    def new_connection(self, conn):
        pass

    @abc.abstractmethod
    def send_server(self, data, conn) -> bytes:
        return data

    @abc.abstractmethod
    def send_client(self, data, conn) -> bytes:
        return data

    @abc.abstractmethod
    def finish_connection(self, conn):
        pass


# Example plugin
# Must be inherited from PluginBase
# and implement all abstract methods
# proxy server will call ExamplePlugin
class ExamplePlugin(PluginBase):
    def new_connection(self, conn):
        print('Start')
        pass

    def send_server(self, data, conn):
        print(data)
        return data

    def send_client(self, data, conn):
        print(data)
        return data

    def finish_connection(self, conn):
        print('End')
        print('********')
        print(conn.buffer_server)
        print('********')
        print(conn.buffer_client)
        pass
