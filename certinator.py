from gevent import subprocess
from OpenSSL import crypto
from Crypto.Util import asn1
import sys
import gevent
import urllib
import random
import logging
import requests
from flask import Flask, request
import re
import os
import psycopg2
import urlparse


urlparse.uses_netloc.append('postgres')
database_url = urlparse.urlparse(os.getenv('DATABASE_URL'))


subprocess_pool = gevent.pool.Pool(10)

domains_done = set()
fingerprints_done = set()


def db_connection():
    logging.info('im connected for real')
    conn = psycopg2.connect(
        database=database_url.path[1:],
        user=database_url.username,
        password=database_url.password,
        host=database_url.hostname,
        port=database_url.port
    )
    conn.autocommit = True
    while True:
        yield conn


get_database_connection = db_connection()


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
    input_string = input_string.strip()
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, input_string)
    fingerprint = cert.digest('sha1').strip()
    subject_hash = cert.subject_name_hash()

    if fingerprint not in fingerprints_done:
        conn = get_database_connection.next()
        with conn.cursor() as cursor:
            logging.info('going to insert %s', subject_hash)
            try:
                cursor.execute(
                    "INSERT INTO certificates (fingerprint, pem, subject_hash) "
                    "VALUES (%s, %s, %s);",
                    (fingerprint, input_string, subject_hash),
                )
            except:
                pass
        fingerprints_done.add(fingerprint)
    return cert


def get_chain_for_cert(cert):
    issuer_hash = cert.get_issuer().hash()
    if certificate_is_signed_by_authority(cert, cert):
        return [cert]
    conn = get_database_connection.next()
    with conn.cursor() as cursor:
        cursor.execute(
            "SELECT fingerprint, pem FROM certificates WHERE subject_hash = '%s';"
            % issuer_hash
        )
        for fingerprint, pem in cursor:
            possible_signer = get_cert_from_string(pem)
            if certificate_is_signed_by_authority(cert, possible_signer):
                return get_chain_for_cert(possible_signer) + [cert]
    raise Exception('no chain found')


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
        logging.info(signature_algorithm)
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
            gevent.spawn(get_cert_from_string, cert_string)


app = Flask(__name__)


@app.route('/domain/<domain_name>', methods=['POST'])
def analyze_domain_name(domain_name, find_chain=True):
    logging.info('querying %s' % domain_name)
    chain = list(get_certs_from_domain(domain_name))
    logging.info('domain %s, found %d certificates' % (domain_name, len(chain)))
    if find_chain and len(chain) > 0:
        try:
            found_chain = list(get_chain_for_cert(chain[0]))
            logging.info('Chain found!')
            for cert in found_chain:
                logging.info(cert.get_subject())
            return ''.join(
                crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
                for cert
                in found_chain
            )
        except Exception as err:
            logging.warning('Chain not found...', err)
    return 'Chain not found, please include intermediates'


regex = re.compile('analyze.html\?d=(?P<domain>[^\"]+)')


@app.route('/process-local-certs/', methods=['POST'])
def process_local_certs():
    gevent.spawn(get_certs_from_file, '/etc/ssl/certs/ca-certificates.crt')
    return 'Done!'


@app.route('/certs')
def list_all_certs():
    conn = get_database_connection.next()
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM certificates;")
        for record in cursor:
            logging.info(record)
    return 'Listing in log!'


@app.route('/')
def hello():
    return 'post to /domain/MY.DOMAIN.NAME\n'


def fetch_certs():
    while True:
        response = requests.get('https://www.ssllabs.com/ssltest/').text
        domains = [urllib.unquote(x) for x in regex.findall(response)]
        random.shuffle(domains)
        for domain in domains:
            if domain not in domains_done:
                subprocess_pool.spawn(analyze_domain_name, domain, False)
                domains_done.add(domain)
        gevent.sleep(60)


gevent.Greenlet.spawn(fetch_certs)
