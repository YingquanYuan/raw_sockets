import re

import HttpClient as C


DEF_URI = '/'
DEF_FILE_NAME = 'index.html'


def urlretrieve(url, port, directory, iface='eth0', reporthook=None):
    '''
    Retrieve the file at the given url to local with
    the given filename
    '''
    hostname, uri, filename = _parse_url(url)
    client = C.HttpClient(hostname, port, iface)
    rc, headers, content = client.GET(uri)
    filepath = '/'.join([directory, filename])
    with open(filepath, 'w') as f:
        f.write(content)
    return filepath


def _parse_url(url):
    '''
    Return the host name, uri and file name in the
    given url, if there is no file name in the url,
    use default 'index.html'
    '''
    _check_url_format(url)
    matcher = re.search('[/]{2}([^\s/]+)(/.*)?', url)
    hostname = matcher.group(1)
    uri = matcher.group(2)
    if not uri:
        uri = DEF_URI
    matcher = re.search('(/[^\s/]+)*/([^\s/]*)$', uri)
    filename = matcher.group(2)
    if not filename:
        filename = DEF_FILE_NAME
    return hostname, uri, filename


def _check_url_format(url):
    '''
    Return True if the given url is in valid format.
    The valid format of an url should be:
    http(s)://hostname(/uri)
    '''
    pattern = re.compile('^http[s]?:[/]{2}[^\s/]+(/[\s]*)?')
    matcher = pattern.match(url)
    if not matcher:
        raise ValueError('Invalid url format')
