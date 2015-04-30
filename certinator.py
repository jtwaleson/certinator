import subprocess
from OpenSSL import crypto
from Crypto.Util import asn1
import sys
import logging
import requests
from flask import Flask, request
import re

logging.basicConfig(
    level=logging.DEBUG,
    stream=sys.stdout,
    format='%(levelname)s: %(message)s',
)


def get_certs_from_lines(lines):
    result = []
    for line in lines:
        line = line.strip()
        if len(result) > 0 or line == '-----BEGIN CERTIFICATE-----':
            result.append(line)
        if line == '-----END CERTIFICATE-----':
            yield '\n'.join(result)
            result = []


def get_cert_from_string(input_string):
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, input_string)
    print(cert.digest('sha1'))
    return cert


def get_certs_from_domain(domain, port=443):
    process = subprocess.Popen([
        'openssl', 's_client',
        '-servername', domain,
        '-connect', '%s:%d' % (domain, port),
        '-showcerts',
    ], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate(b'')
    for cert_string in get_certs_from_lines(out.decode().split('\n')):
        yield get_cert_from_string(cert_string)


def certificate_is_signed_by_authority(certificate, authority):
    signature_algorithm = certificate.get_signature_algorithm()
    certificate_asn1 = crypto.dump_certificate(crypto.FILETYPE_ASN1, certificate)
    certificate_der = asn1.DerSequence()
    certificate_der.decode(certificate_asn1)
    der_cert, der_algo, der_sig = certificate_der
    der_sig_in = asn1.DerObject()
    der_sig_in.decode(der_sig)
    sig0 = der_sig_in.payload
    if sig0[0] != '\x00':
        raise Exception('Number of unused bits is strange')
    sig = sig0[1:]
    try:
        crypto.verify(authority, sig, der_cert, signature_algorithm)
        return True
    except crypto.Error:
        return False
    return False


def reader(file_handle):
    last_result = None
    while last_result != '':
        last_result = file_handle.readline()
        yield last_result


def get_certs_from_file(file_name):
    with open(file_name, 'r') as file_handle:
        for cert_string in get_certs_from_lines(reader(file_handle)):
            yield get_cert_from_string(cert_string)


app = Flask(__name__)


@app.route('/domain/<domain_name>', methods=['POST'])
def analyze_domain_name(domain_name):
    result = '\n'.join([
        cert.digest('sha1')
        for cert
        in get_certs_from_domain(domain_name)
    ]) + '\n'
    logging.info('query for %s yielded: \n%s' % (domain_name, result))
    return result


regex = re.compile('analyze.html\?d=(?P<domain>[^\"]+)')


@app.route('/find-domain-names-from-url/', methods=['POST'])
def find_domain_names_in_url():
    url = request.data
    response = requests.get(url).text
    for domain in regex.findall(response):
        try:
            analyze_domain_name(domain)
        except:
            pass
    return 200


@app.route('/')
def hello():
    return 'post to /domain/MY.DOMAIN.NAME\n'
