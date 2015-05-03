import sys
import logging
from flask import Flask, Response, request
from util import is_valid_hostname_and_port
import warehouse
import certificate_operations


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
            yield certificate_operations.get_subject_string(cert) + '\n'
    return Response(gen())


@app.route('/check-domain/<domain>', methods=['POST'])
@app.route('/check-domain/<domain>:<port>', methods=['POST'])
def analyze_domain_name(domain, port=443):
    if not is_valid_hostname_and_port(domain, port):
        return ('Invalid hostname/port', 400)
    port = int(port)

    logging.info('Fetching certificates from %s:%d' % (domain, port))

    added = 0
    try:
        for cert in certificate_operations.get_certs_from_domain(domain, port):
            if warehouse.store(cert):
                added += 1
    except Exception as e:
        logging.exception('Could not handle %s:%d' % (domain, port))
        return str(e), 500

    return 'domain checked, thanks for submitting %d new certificates' % added


def get_certificates_from_request(request):
    files_count = 0
    for name, uploaded_file in request.files.iteritems():
        files_count += 1
        pem_strings = certificate_operations.get_pem_strings_from_file_handle(
            uploaded_file
        )
        for pem_string in pem_strings:
            yield (
                files_count,
                certificate_operations.get_cert_from_pem_string(pem_string),
            )

    if files_count == 0:
        files_count += 1
        pem_strings = certificate_operations.get_pem_strings_from_lines(
            request.data.split('\n')
        )
        for pem_string in pem_strings:
            yield (
                files_count,
                certificate_operations.get_cert_from_pem_string(pem_string),
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
        if not certificate_operations.certificate_is_signed_by_authority(
            cert, cert
        ):
            likely_certificate = cert
            break

    if likely_certificate is None:
        return 'No certificates found in request', 400

    def response_generator(cert):
        previous_cert = None
        # we don't output the last cert from the chain, that is self-signed
        for chain_cert in certificate_operations.get_certificate_chain(cert):
            if previous_cert:
                yield previous_cert
            previous_cert = certificate_operations.get_pem_string_from_cert(
                chain_cert
            )

    return Response(response_generator(likely_certificate))
