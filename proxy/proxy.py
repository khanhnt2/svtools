import socketserver
import argparse
import threading
import socket
import select
import logging
import importlib
import pkgutil
import traceback
import cmd
import inspect
import datetime
import os
from base import PluginBase


thread_lock = threading.Lock()
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%H:%M:%S')


class Connection:
    __conn_id = 0

    def __init__(self, app_name, sock_client, sock_server, chunk_size=1024, buffer_size=5 * 1024):
        self.__client = sock_client
        self.__server = sock_server
        self.__app_name = app_name
        self._max_chunk_size = chunk_size
        self._max_buffer_size = buffer_size
        self._datetime = str(datetime.datetime.now())
        # total data server has sent
        self.buffer_server = b''
        # total data client has sent
        self.buffer_client = b''
        thread_lock.acquire(True)
        Connection.__conn_id += 1
        self.__id = Connection.__conn_id
        thread_lock.release()

    @property
    def client(self):
        return self.__client

    @property
    def datetime(self):
        return self._datetime

    @property
    def app_name(self):
        return self.__app_name

    @property
    def server(self):
        return self.__server

    @property
    def max_chunk_size(self):
        return self._max_chunk_size

    @property
    def max_buffer_size(self):
        return self._max_buffer_size

    @property
    def id(self):
        return self.__id

    def clean_buffer(self):
        if len(self.buffer_server) >= self.max_buffer_size:
            self.buffer_server = b''
        if len(self.buffer_client) >= self.max_buffer_size:
            self.buffer_client = b''


class PluginManager:

    class Plugin:
        def __init__(self, name, instance: PluginBase):
            self.enable = instance.enable
            self.name = name
            self.instance = instance

    def __init__(self, path='plugins'):
        self._enable = True
        self.__modules = []
        self.__plugins = []
        self.path = path
        self.loaded_modules = []
        self._app_path = None

    @property
    def plugins(self):
        return self.__plugins

    @property
    def app_path(self):
        return self._app_path

    @app_path.setter
    def app_path(self, path):
        self._app_path = path  # os.path.join(self.path, path)
        # create app_path plugins folder
        app_plugin_path = os.path.join(self.path, self._app_path)
        if not os.path.exists(app_plugin_path):
            os.makedirs(app_plugin_path)

    def reload(self):
        self.__modules = []
        self.__plugins = []
        self.load(True)

    def load(self, _reload=False):
        '''Dynamic module loading'''
        # https://github.com/cuckoosandbox/cuckoo/blob/master/cuckoo/core/plugins.py#L29
        for _, module_name, _ in pkgutil.iter_modules([self.path], self.path + '.'):
            try:
                if _reload:
                    module = importlib.import_module(module_name)
                    self.__modules.append(importlib.reload(module))
                else:
                    self.__modules.append(importlib.import_module(module_name))
            except Exception as e:
                logging.error('Unable to load %s: %s' % (module_name, e))

        for _, module_name, _ in pkgutil.iter_modules([os.path.join(self.path, self._app_path)], self.path + '.' + self._app_path + '.'):
            try:
                if _reload:
                    module = importlib.import_module(module_name)
                    self.__modules.append(importlib.reload(module))
                else:
                    self.__modules.append(importlib.import_module(module_name))
            except Exception as e:
                logging.error('Unable to load %s: %s' % (module_name, e))

        for module in self.__modules:
            class_members = inspect.getmembers(module, inspect.isclass)
            for name, _class in class_members:
                if not issubclass(_class, PluginBase) or name == 'PluginBase':
                    continue
                try:
                    module = _class()
                    self.__plugins.append(self.Plugin(name, _class()))
                except Exception as e:
                    logging.error(e)
                    traceback.print_exc()
        self.__plugins = sorted(self.__plugins, key=lambda x: x.instance.priority)
        logging.info('Loaded plugins: ' + str(self.loaded))
        logging.info('Running plugins: ' + str(self.running))

    @property
    def loaded(self):
        '''List loaded modules'''
        return [inst.name for inst in self.__plugins]

    @property
    def running(self):
        '''List running modules'''
        return [inst.name for inst in self.__plugins if inst.enable]

    def enable(self):
        '''Enable all plugins'''
        self._enable = True

    def disable(self):
        '''Disable all plugins'''
        self._enable = False

    def disable_plugin(self, name):
        '''Disable plugin by name'''
        for plugin in self.__plugins:
            if plugin.name == name:
                plugin.enable = False
                break

    def enable_plugin(self, name):
        '''Enable plugin by name'''
        for plugin in self.__plugins:
            if plugin.name == name:
                plugin.enable = True

    def do_new_connection(self, conn: Connection):
        if self._enable:
            for plugin in self.__plugins:
                if plugin.enable:
                    try:
                        plugin.instance.new_connection(conn)
                    except Exception as e:
                        logging.error(plugin.name + '.new_connection ' + str(e))

    def do_send_server(self, data: bytes, conn: Connection) -> bytes:
        if self._enable:
            for plugin in self.__plugins:
                if plugin.enable:
                    try:
                        data = plugin.instance.send_server(data, conn)
                    except Exception as e:
                        logging.error(plugin.name + '.send_server ' + str(e))
        return data

    def do_send_client(self, data: bytes, conn: Connection) -> bytes:
        if self._enable:
            for plugin in self.__plugins:
                if plugin.enable:
                    try:
                        data = plugin.instance.send_client(data, conn)
                    except Exception as e:
                        logging.error(plugin.name + '.send_client ' + str(e))
        return data

    def do_finish_connection(self, conn: Connection):
        if self._enable:
            for plugin in self.__plugins:
                if plugin.enable:
                    try:
                        plugin.instance.finish_connection(conn)
                    except Exception as e:
                        logging.error(plugin.name + '.finish_connection ' + str(e))


class ProxyHandler(socketserver.BaseRequestHandler):
    def setup(self):
        global TARGET_IP
        global TARGET_PORT

        sock_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_server.connect((TARGET_IP, TARGET_PORT))
        # self.server is instance of ProxyServer
        self.conn = Connection(self.server.app_name, self.request, sock_server)
        # logging.info('Open connection %d' % self.conn.id)
        # create new app_name folder
        if not os.path.exists(self.server.app_name):
            os.makedirs(self.server.app_name)
        # call plugin
        self.server.plugin.do_new_connection(self.conn)

    def handle(self):
        while True:
            try:
                readable, writable, exceptions = select.select((self.conn.client, self.conn.server), [], [])
                for s in readable:
                    chunk = s.recv(self.conn.max_chunk_size)
                    if len(chunk) == 0:
                        return
                    if s == self.conn.client:
                        chunk = self.server.plugin.do_send_server(chunk, self.conn)
                        self.conn.buffer_client += chunk
                        self.conn.server.send(chunk)
                    elif s == self.conn.server:
                        chunk = self.server.plugin.do_send_client(chunk, self.conn)
                        self.conn.buffer_server += chunk
                        self.conn.client.send(chunk)
                self.conn.clean_buffer()
            except socket.error:
                break
            except Exception as e:
                logging.error(e)
                traceback.print_exc()
                break

    def finish(self):
        self.conn.client.close()
        # logging.info('Close connection %d' % self.conn.id)
        self.server.plugin.do_finish_connection(self.conn)


class ProxyServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, app_name, server_address, handler, plugin: PluginManager):
        socketserver.TCPServer.__init__(self, server_address, handler)
        self.plugin = plugin
        self.app_name = app_name


class Console(cmd.Cmd):
    prompt = '> '

    def preloop(self):
        global TARGET_IP
        global TARGET_PORT
        global HOST_IP
        global HOST_PORT
        global APP_NAME

        self.plugin = PluginManager()
        self.plugin.app_path = APP_NAME
        self.plugin.load()
        self.proxyserver = ProxyServer(APP_NAME, (HOST_IP, HOST_PORT), ProxyHandler, self.plugin)

        thread = threading.Thread(target=self.proxyserver.serve_forever)
        thread.start()

    def do_reload(self, arg: str):
        '''Reload rules'''
        self.plugin.reload()

    def do_loaded(self, arg: str):
        '''List loaded plugins'''
        print(str(self.plugin.loaded))

    def do_enable(self, arg: str):
        '''Enable plugins'''
        # can use argparse to parse arg
        if len(arg) == 0:
            # disable all plugins
            self.plugin.enable()
        else:
            # disable plugin by name
            plugin_names = arg.split(' ')
            for name in plugin_names:
                self.plugin.enable_plugin(name)
        self.do_running(None)

    def do_running(self, arg: str):
        if not self.plugin.enable:
            print('[]')
        else:
            print(str(self.plugin.running))

    def do_disable(self, arg: str):
        '''Disable plugins'''
        if len(arg) == 0:
            self.plugin.disable()
        else:
            plugin_name = arg.split(' ')
            for name in plugin_name:
                self.plugin.disable_plugin(name)
        self.do_running(None)

    def do_exit(self, arg: str):
        '''Exit program'''
        self.proxyserver.server_close()
        return True

    def postloop(self):
        self.do_exit(None)

    def keyboard_interrupt(self):
        self.do_exit(None)


def main():
    global TARGET_IP
    global TARGET_PORT
    global HOST_IP
    global HOST_PORT
    global APP_NAME

    parser = argparse.ArgumentParser(description='Proxy server')
    parser.add_argument('app_name', type=str, help='Application name')
    parser.add_argument('app_server', type=str, help='Target IP')
    parser.add_argument('app_port', type=int, help='Target port')
    parser.add_argument('listen_ip', type=str, help='Host IP')
    parser.add_argument('listen_port', type=int, help='Host port')
    args = parser.parse_args()
    TARGET_IP = args.app_server
    TARGET_PORT = args.app_port
    APP_NAME = args.app_name
    HOST_IP = args.listen_ip
    HOST_PORT = args.listen_port

    cmd = Console()
    try:
        cmd.cmdloop()
    except KeyboardInterrupt:
        cmd.do_exit(None)
    except Exception as e:
        logging.error('cmd error ' + str(e))


if __name__ == '__main__':
    main()
