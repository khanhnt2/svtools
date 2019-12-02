from base import PluginBase
from graylog import Graylog


# Example plugin
# Must be inherited from PluginBase
# and implement all abstract methods
# proxy server will call ExamplePlugin
class ExamplePlugin(PluginBase):
    def __init__(self):
        self.enable = False
        self.priority = 0
        self.graylog = Graylog()
        
    def new_connection(self, conn):
        '''Will be called when have a new connection'''
        pass

    def send_server(self, data, conn):
        '''Will be called when send data to server'''
        badwords = ['flag']
        lower_data = str(data).lower()

        for word in badwords:
            if word in lower_data:
                # Remove case insentive words
                # data = re.sub(word, '', data, flags=re.IGNORECASE)
                # Log about warning
                self.graylog.warn(word, conn)

        blockwords = ['union']
        for word in blockwords:
            if word in lower_data:
                # Drop connection
                self.drop_connection(conn)
                # Log about this block
                self.graylog.block(word, conn)
        return data

    def send_client(self, data, conn):
        '''Will be called when send data to client'''
        return data

    def finish_connection(self, conn):
        '''Will be called when connection close'''
        pass
