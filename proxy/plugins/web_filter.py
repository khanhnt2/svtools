from base import PluginBase


class WebFilter(PluginBase):
    def __init__(self):
        self.priority = 0

    def new_connection(self, conn):
        pass

    def send_server(self, data, conn):
        # remove compression
        if b'Accept-Encoding: gzip, deflate\r\n' in data:
            data = data.replace(b'Accept-Encoding: gzip, deflate\r\n', b'')
        return data

    def send_client(self, data, conn):
        return data

    def finish_connection(self, conn):
        pass
