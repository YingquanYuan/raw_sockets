import re
import os

from logger import get_logger

TEXT_DELIM = "\r\n\r\n"
LINE_DELIM = "\r\n"
HEADER_DELIM = ":"
FIELD_DELIM = ";"
PARAM_DELIM = "="
# regex matching href in HTML
HREF_REG = r'<a[^>]+href\s*=\s*["\']([^\s@]+)["\'][^>]*>[^<>]+</a>'
# regex matching a full or partial url
URL_REG = r'(https?://([^\s/]+))?([^\s]*)'


class HttpParser:
    """
    The HTTP parser for the Web Crawler
    This parser is fail-fast for strict network programs

    Regexes:
    match all href in HTML:
        r'<a[^>]+href\s*=\s*["\']([^\s@]+)["\'][^>]*>[^<>]+</a>'

    match a full or partial url
        r'(https?://([^\s/]+))?([^\s]*)'

    match secret_flag in HTML:
        r'secret_flag[^>]*>FLAG:\s*([0-9a-zA-Z]{64})<'
    """
    def __init__(self, target_reg=''):
        self.logger = get_logger(os.path.basename(__file__))
        self.logger.debug("Initializing HTTP parser")
        self.href_ptn = re.compile(HREF_REG)
        self.url_ptn = re.compile(URL_REG)
        self.target_ptn = re.compile(target_reg)

    def parse_secret(self, html):
        return self.target_ptn.findall(html)

    def parse_urls(self, html):
        """
        parse out urls from all href tags in the given html
        """
        return self.href_ptn.findall(html)

    def parse_url(self, url):
        """
        parse the give url into a host field and uri field
        e.g.
        (http://(cs5700.ccs.neu.edu))(/accounts/login/?next=/fakebook/)
                   host (group(2))            uri (group(3))
        """
        matcher = self.url_ptn.match(url)
        if matcher:
            host = matcher.group(2)
            uri = matcher.group(3)
            return host, uri
        else:
            self.logger.error("Cannot parse the url: %s"
                              % url)
            raise RuntimeError()

    def split_response(self, response):
        start_delim = response.find(TEXT_DELIM)
        if start_delim > 0:
            headers = response[:start_delim]
            html = response[start_delim + len(TEXT_DELIM):]
            return headers, html
        else:
            self.logger.error("Cannot find the text delimiter "
                              + r"\r\n\r\n in HTTP response")
            self.logger.debug("Response:\n%s" % response)
            raise RuntimeError()

    def get_response_code(self, response):
        status_delim = response.find(LINE_DELIM)
        if status_delim > 0:
            status = response[:status_delim]
            response_code = status.split()[1]
            return response_code.strip()
        else:
            self.logger.error("Cannot find the status line in HTTP response")
            self.logger.debug("Response:\n%s" % response)
            raise RuntimeError()

    def get_header_values(self, headers, header_key):
        header_values = []
        while headers.find(LINE_DELIM) > 0:
            header, headers = headers.split(LINE_DELIM, 1)
            if header.strip().startswith(header_key):
                header_values.append(header.split(HEADER_DELIM, 1)[1].strip())
        if header_values:
            return header_values
        else:
            self.logger.error("HTTP header:%s was not found"
                              % header_key)
            self.logger.debug("Headers:\n%s" % headers)
            raise RuntimeError()

    def get_header_parameter(self, header_values, param_key):
        for header_value in header_values:
            fields = header_value.split(FIELD_DELIM)
            for field in fields:
                if field.strip().startswith(param_key):
                    return field.split(PARAM_DELIM)[1].strip()
        else:
            self.logger.error("cannot find the parameter value for key: %s"
                              % param_key)
            self.logger.debug("Header Values:\n%s" % header_values)
            raise RuntimeError()
