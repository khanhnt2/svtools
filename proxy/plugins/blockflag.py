from base import PluginBase
from graylog import Graylog

class BlockFlag(PluginBase):
    def __init__(self):
        self.enable = True
        self.priority = 0
        self.graylog = Graylog()
        
    def new_connection(self, conn):
        '''Will be called when have a new connection'''
        pass

    def send_server(self, data, conn):
        return data

    def send_client(self, data, conn):
        lower_data = str(data).lower()
        blockwords = ['svattt{', '{tttavs', 'u1zbvfru', 'vfruqvzt', 'svattt2019{', '{9102tttavs', 'u1zbvfrumjaxo']
        for word in blockwords:
            if word in lower_data:
                # Drop connection
                self.drop_connection(conn)
                # Log about this block
                self.graylog.block(word, conn)
        return data

    def finish_connection(self, conn):
        '''Will be called when connection close'''
        pass
