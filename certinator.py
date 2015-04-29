#!/usr/bin/python

import subprocess
from OpenSSL import crypto
from Crypto.Util import asn1


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
    certs = [get_cert_from_string(c) for c in get_certs_from_lines(out.decode())]
    verify_certificate_to_authority(certs[1], certs[2])


def verify_certificate_to_authority(certificate, authority):
    signature_algorithm = certificate.get_signature_algorithm()
    # Get the ASN1 format of the certificate
    certificate_asn1 = crypto.dump_certificate(crypto.FILETYPE_ASN1, certificate)
    certificate_der = asn1.DerSequence()
    certificate_der.decode(certificate_asn1)
    # The certificate has three parts:
    # - certificate
    # - signature algorithm
    # - signature
    # http://usefulfor.com/nothing/2009/06/10/x509-certificate-basics/
    der_cert, der_algo, der_sig = certificate_der

    # The signature is a BIT STRING (Type 3)
    # Decode that as well
    der_sig_in = asn1.DerObject()
    der_sig_in.decode(der_sig)
    sig0 = der_sig_in.payload
    if sig0[0] != '\x00':
        raise Exception('Number of unused bits is strange')

    # Now get the signature itself
    sig = sig0[1:]

    # And verify the certificate
    crypto.verify(authority, sig, der_cert, signature_algorithm)
    print "Certificate looks good"


if __name__ == '__main__':
    get_certs_from_domain('www.google.com')
