import sys
import logging
from flask import Flask, Response
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
    certs = warehouse.get_most_recent_certificates(5)

    def generator(certs):
        for cert in certs:
            yield cert.digest('sha1') + '\n'

    return Response(generator(certs))


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
    except:
        logging.exception('dsads')
        return 'Could not get certificates from domain', 500

    return 'domain checked, thanks for submitting %d new certificates' % added
