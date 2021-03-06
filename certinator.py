import sys
import re
import logging
from flask import Flask, request, render_template, jsonify, redirect
from util import is_valid_hostname_and_port
import warehouse
import x509_util


logging.basicConfig(
    level=logging.DEBUG,
    stream=sys.stdout,
    format='%(levelname)s: %(message)s',
)


app = Flask(__name__)


TEXT = 'text'
JSON = 'json'
HTML = 'html'


def json_html_text(request):
    best = request.accept_mimetypes.best_match([
        'text/plain',
        'application/x-pem-file',
        'text/html',
        'application/json',
        'application/xhtml+xml',
        'application/xml',
    ], default='*/*')
    logging.info('best match is %s' % best)
    if best in ('application/json',):
        return JSON
    elif best in (
        'text/html',
        'application/xml',
        'application/xhtml+xml',
    ):
        return HTML
    else:
        return TEXT


@app.route('/')
def index():
#    def gen():
#        for domain in warehouse.get_last_scanned_domains():
#            yield domain.strip() + '\n'
#        for cert in warehouse.get_last_added_certificates():
#            yield cert.get_subject_string() + '\n'
    response_format = json_html_text(request)
    if response_format == TEXT:
        return 'welcome to the server'
    elif response_format == HTML:
        return render_template('index.html')
    else:
        return 'can not send data in this format', 415


fingerprint_regex = re.compile('[A-F0-9]{40}')


@app.route('/certificate/<fingerprint>')
def get_certificate(fingerprint):
    fingerprint = fingerprint.upper().replace(':', '')
    if not fingerprint_regex.match(fingerprint):
        return 'not a valid certificate fingerprint', 400
    cert = warehouse.get_by_fingerprint(fingerprint)
    response_format = json_html_text(request)
    if cert is None:
        return 'not found', 404
    elif response_format == TEXT:
        return cert.get_pem()
    elif response_format == HTML:
        try:
            chain = list(cert.get_chain())
            return render_template('certificate.html', certificates=chain)
        except:
            return render_template(
                'certificate.html', certificates=[cert],
                warnings=[
                    'Could not get certificate chain',
                ],
            )
    else:
        return jsonify(cert.get_details())


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
    response_format = json_html_text(request)
    if len(signers) == 0:
        return 'no signers found', 404
    elif response_format == JSON:
        return jsonify([x.get_details() for x in signers])
    elif response_format == HTML:
        return 'unable to output signers in html, stay tuned', 415
    else:
        return '\n'.join(x.get_fingerprint() for x in signers) + '\n'


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

    files_count += 1
    if 'certtext' in request.form:
        pem_strings = x509_util.get_pem_strings_from_lines(
            request.form['certtext'].split('\n')
        )
    else:
        pem_strings = x509_util.get_pem_strings_from_lines(
            request.data.split('\n')
        )
    for pem_string in pem_strings:
        yield (
            files_count,
            x509_util.get_cert_from_pem_string(pem_string),
        )


@app.route('/upload', methods=['GET'])
def get_chain_page():
    return render_template('upload.html')


@app.route('/upload', methods=['POST'])
def get_chain():
    likely_certificate = None
    for file_no, cert in get_certificates_from_request(request):
        if not cert.is_self_signed():
            likely_certificate = cert
            break

    if likely_certificate is None:
        return 'No certificates found in request', 400

    return redirect(
        '/certificate/%s?chain=true'
         % likely_certificate.get_fingerprint()
    )
