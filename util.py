import re


def is_valid_hostname_and_port(hostname, port):
    try:
        port = int(port)
    except ValueError:
        return False
    if port < 1 or port > 65535:
        return False

    if len(hostname) > 255:
        return False
    if hostname[-1] == '.':
        hostname = hostname[:-1]
    allowed = re.compile('(?!-)[A-Z\d-]{1,63}(?<!-)$', re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split('.'))
