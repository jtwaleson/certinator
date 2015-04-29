#!/usr/bin/python

import subprocess
from OpenSSL import crypto


def get_certs_from_lines(lines):
    lines = [line.strip() for line in lines.split('\n')]
    result = []
    for line in lines:
        if len(result) > 0 or line == '-----BEGIN CERTIFICATE-----':
            result.append(line)
        if line == '-----END CERTIFICATE-----':
            yield '\n'.join(result)
            result = []


def get_cert_from_string(input_string):
    return crypto.load_certificate(crypto.FILETYPE_PEM, input_string)


def get_certs_from_domain(domain, port=443):
    process = subprocess.Popen([
        'openssl', 's_client',
        '-servername', domain,
        '-connect', '%s:%d' % (domain, port),
        '-showcerts',
    ], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate(b'')
    for cert in get_certs_from_lines(out.decode()):
        print('cert found!')
        cert = get_cert_from_string(cert)
        print(cert.get_issuer())
        print(cert.get_subject())
        print(dir(cert))


if __name__ == '__main__':
    get_certs_from_domain('www.google.com')
