import requests
import logging
import threading


class Graylog:
    def __init__(self):
        self.url = "http://192.168.56.117:12201/gelf"
        self.headers = {'Content-Type': 'application/json'}
        self.timeout = 2.0

    def log_data(self, data, conn, who_send):
        t = threading.Thread(target=self.__log_data, args=(data, conn, who_send))
        t.start()

    def __log_data(self, data, conn, who_send):
        _data = str(data)
        sdata = {"version": "1.1", "host": conn.app_name, 'short_message': _data, "level": 5, 'conn_id': conn.id, 'datetime': conn.datetime, 'who_send': who_send}
        self.__send(sdata)

    def __warn(self, keyword, conn):
        sdata = {"version": "1.1", "host": conn.app_name, 'short_message': "Warn matched keyword", "level": 1, 'conn_id': conn.id, 'datetime': conn.datetime, 'keyword': str(keyword)}
        self.__send(sdata)

    def warn(self, keyword, conn):
        t = threading.Thread(target=self.__warn, args=(keyword, conn,))
        t.start()

    def __block(self, keyword, conn):
        sdata = {"version": "1.1", "host": conn.app_name, 'short_message': "Block matched keyword", "level": 0, 'conn_id': conn.id, 'datetime': conn.datetime, 'keyword': str(keyword)}
        self.__send(sdata)

    def block(self, keyword, conn):
        t = threading.Thread(target=self.__block, args=(keyword, conn,))
        t.start()

    def __send(self, json_data):
        try:
            requests.post(self.url, json=json_data, headers=self.headers, timeout=self.timeout)
        except Exception as e:
            logging.error('Send graylog:' + str(e))
