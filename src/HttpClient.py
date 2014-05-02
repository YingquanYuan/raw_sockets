import rawsocket as s
import os

import HttpParser as P
from logger import get_logger

DELIM = "\r\n"
BLANK = ""
RECVBUFSIZE = 65535
RC = {
    "200": "OK",
    "301": "Moved",
    "302": "Found",
    "403": "Forbidden",
    "404": "Not Found",
    "500": "Internal Error",
}


class HttpClient:
    """
    A simple HTTP client wrapper based on socket
    ONE client per host
    """
    def __init__(self, server, port=80, iface='eth0'):
        self.logger = get_logger(os.path.basename(__file__))
        self.logger.debug("Initializing the HTTP client for host %s"
                          % server)
        self.server = server
        self.port = port
        self.iface = iface
        self.GET_BASE = self._GET_base()
        self.http_params = {
            "uri": BLANK,
        }
        self.parser = P.HttpParser()
        self.socket = None

    def GET(self, uri):
        self.http_params["uri"] = uri
        response = self._send_request(self.GET_BASE, **self.http_params)
        response_code = self.parser.get_response_code(response)
        headers, content = self._process_response(
            response_code, response, self.GET_BASE, **self.http_params)
        return response_code, headers, content

    def _send_request(self, req_base, **params):
        self.logger.debug("[Request: %s]" % params["uri"])
        request = req_base % params
        self.socket = self._new_connection()
        self.socket.send(request)
        response = ''
        buffer = self.socket.recv(RECVBUFSIZE)
        while buffer:
            response += buffer
            buffer = self.socket.recv(RECVBUFSIZE)
        self._close_connection()
        self.logger.debug(self.socket.dump_metrics()[0])
        return response

    def _process_response(self, rc, response, req_base, **params):
        headers, content = self.parser.split_response(response)
        if rc in ("200",):  # just return the content if OK
            self.logger.debug("[Response: %s %s, URL: %s], OK"
                              % (rc, RC[rc], params["uri"]))
            return headers, content
        else:   # abort if recv non-200 response
            self.logger.error("[Response: %s, URL: %s], quit"
                              % (rc, params["uri"]))
            raise ValueError('Get a non-200 response')

    def _new_connection(self):
        socket = s.RawSocket(self.iface)
        socket.connect((self.server, self.port))
        return socket

    def _close_connection(self):
        if self.socket:
            self.socket.close()

    def _GET_base(self):
        """
        Return a GET request string with placeholder
        """
        GET_BASE = "GET %(uri)s HTTP/1.1" + DELIM + \
            "From: yuan.yin@husky.neu.edu" + DELIM + \
            "User-Agent: enzen/1.0" + DELIM + \
            "Host: david.choffnes.com" + DELIM + \
            "Connection: Keep-Alive" + DELIM + \
            DELIM
        return GET_BASE
