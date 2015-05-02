from OpenSSL import crypto
from gevent import subprocess
from Crypto.Util import asn1

import warehouse


def get_pem_strings_from_lines(lines):
    result = []
    for line in lines:
        line = line.strip()
        if len(result) > 0 or line == '-----BEGIN CERTIFICATE-----':
            result.append(line)
        if line == '-----END CERTIFICATE-----':
            yield '\n'.join(result)
            result = []


def get_pem_string_from_cert(cert):
    return crypto.dump_certificate(crypto.FILETYPE_PEM, cert)


def get_cert_from_pem_string(input_string):
    input_string = input_string.strip()
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, input_string)
    return cert


def get_certs_from_domain(domain, port):
    process = subprocess.Popen([
        'timeout', '5',
        'openssl', 's_client',
        '-servername', domain,
        '-connect', '%s:%d' % (domain, port),
        '-showcerts',
    ], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate(b'')
    if process.returncode != 0:
        raise Exception('Could not get certificates from domain')

    for cert_string in get_pem_strings_from_lines(out.decode().split('\n')):
        yield get_cert_from_pem_string(cert_string)


def certificate_is_signed_by_authority(certificate, authority):
    signature_algorithm = certificate.get_signature_algorithm()
    certificate_asn1 = crypto.dump_certificate(
        crypto.FILETYPE_ASN1, certificate
    )
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


def get_certificate_chain(cert):
    seen = set()
    while True:
        fingerprint = cert.digest('sha1')
        if fingerprint in seen:
            raise Exception('cycle detected')
        seen.add(fingerprint)

        yield cert

        if certificate_is_signed_by_authority(cert, cert):
            # self signed, end of the line
            return

        issuers = list(get_signers_for_cert(cert))

        if len(issuers) == 0:
            raise Exception('can not find chain')

        for issuer in issuers:
            if certificate_is_signed_by_authority(issuer, issuer):
                cert = issuer
                break
        else:
            cert = issuers[0]


def get_subject_string(cert):
    return ', '.join('%s=%s' % (x, y) for x, y in cert.get_subject().get_components()) + '\n'


def get_signers_for_cert(cert):
    if certificate_is_signed_by_authority(cert, cert):
        yield None
        return
    for possible_signer in warehouse.get_by_subject(cert.get_issuer()):
        if certificate_is_signed_by_authority(cert, possible_signer):
            yield possible_signer
