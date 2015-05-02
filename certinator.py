import sys
import gevent
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


@app.route('/check-domain/<domain>', methods=['POST'])
@app.route('/check-domain/<domain>:<port>', methods=['POST'])
def analyze_domain_name(domain, port=443):
    if not is_valid_hostname_and_port(domain, port):
        return ('Invalid hostname/port', 400)
    port = int(port)
    logging.info('Fetching certificates from %s:%d' % (domain, port))
    certs = list(certificate_operations.get_certs_from_domain(domain, port))

    for cert in certs:
        warehouse.store(cert)

    def return_certs(certs):
        for cert in certificate_operations.get_certificate_chain(certs[0]):
            yield certificate_operations.get_subject_string(cert)
            yield certificate_operations.get_pem_string_from_cert(cert)

    return Response(return_certs(certs))




#    return 'Found %d certificates' % len(certs)
#    chain = list(get_certs_from_domain(domain_name))
#    logging.info('domain %s, found %d certificates' % (domain_name, len(chain)))
#    if find_chain and len(chain) > 0:
#        try:
#            found_chain = list(get_chain_for_cert(chain[0]))
#            logging.info('Chain found!')
#            for cert in found_chain:
#                logging.info(cert.get_subject())
#            return ''.join(
#                crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
#                for cert
#                in found_chain
#            )
#        except Exception as err:
#            logging.warning('Chain not found...', err)
