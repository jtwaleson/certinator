import sys
import re
import logging
from flask import Flask, Response, request
from util import is_valid_hostname_and_port
import warehouse
import x509_util


logging.basicConfig(
    level=logging.DEBUG,
    stream=sys.stdout,
    format='%(levelname)s: %(message)s',
)


app = Flask(__name__)


@app.route('/')
def index():
    def gen():
        for domain in warehouse.get_last_scanned_domains():
            yield domain.strip() + '\n'
        for cert in warehouse.get_last_added_certificates():
            yield cert.get_subject_string() + '\n'
    return Response(gen())


fingerprint_regex = re.compile('[A-F0-9]{40}')


@app.route('/certificate/<fingerprint>')
def get_certificate(fingerprint):
    fingerprint = fingerprint.upper().replace(':', '')
    if not fingerprint_regex.match(fingerprint):
        return 'not a valid certificate fingerprint', 400
    cert = warehouse.get_by_fingerprint(fingerprint)
    if cert is None:
        return 'not found', 404
    else:
        return cert.get_pem()


@app.route('/signers/<fingerprint>')
def get_signers(fingerprint):
    fingerprint = fingerprint.upper().replace(':', '')
    if not fingerprint_regex.match(fingerprint):
        return 'not a valid certificate fingerprint', 400
    cert = warehouse.get_by_fingerprint(fingerprint)
    if cert is None:
        return 'not found', 404
    if cert.is_self_signed():
        return 'certificate is self-signed', 409
    signers = list(cert.get_signers())
    if len(signers) == 0:
        return 'no signers found', 404
    else:
        return '\n'.join(x.get_fingerprint() for x in signers)


@app.route('/check-domain/<domain>', methods=['POST'])
@app.route('/check-domain/<domain>:<port>', methods=['POST'])
def analyze_domain_name(domain, port=443):
    if not is_valid_hostname_and_port(domain, port):
        return ('Invalid hostname/port', 400)
    port = int(port)

    logging.info('fetching certificates from %s:%d' % (domain, port))

    added = 0
    try:
        for cert in x509_util.get_certs_from_domain(domain, port):
            if warehouse.store(cert):
                added += 1
    except Exception as e:
        logging.warning('could not handle %s:%d' % (domain, port))
        return str(e), 500

    return (
        'domain %s:%d checked, thanks for submitting %d new certificates' % (
            domain, port, added
        )
    )


def get_certificates_from_request(request):
    files_count = 0
    for name, uploaded_file in request.files.iteritems():
        files_count += 1
        pem_strings = x509_util.get_pem_strings_from_file_handle(
            uploaded_file
        )
        for pem_string in pem_strings:
            yield (
                files_count,
                x509_util.get_cert_from_pem_string(pem_string),
            )

    if files_count == 0:
        files_count += 1
        pem_strings = x509_util.get_pem_strings_from_lines(
            request.data.split('\n')
        )
        for pem_string in pem_strings:
            yield (
                files_count,
                x509_util.get_cert_from_pem_string(pem_string),
            )


@app.route('/upload', methods=['POST'])
def upload_certificates():
    file_count = 0
    cert_count = 0
    for file_no, cert in get_certificates_from_request(request):
        file_count = max(file_no, file_count)
        if warehouse.store(cert):
            cert_count += 1

    return 'uploaded %d files, resulting in %d new certificates' % (
        file_count, cert_count
    )


@app.route('/chain/', methods=['POST'])
def get_chain():
    likely_certificate = None
    for file_no, cert in get_certificates_from_request(request):
        if not cert.is_self_signed():
            likely_certificate = cert
            break

    if likely_certificate is None:
        return 'No certificates found in request', 400

    def response_generator(cert):
        previous_cert = None
        # we don't output the last cert from the chain, that is self-signed
        for chain_cert in x509_util.get_certificate_chain(cert):
            if previous_cert:
                yield previous_cert
            previous_cert = chain_cert.get_pem()

    return Response(response_generator(likely_certificate))
