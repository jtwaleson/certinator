from OpenSSL import crypto
from gevent import subprocess
from Crypto.Util import asn1

import warehouse


class X509Extra(crypto.X509):

    def get_pem(self):
        return crypto.dump_certificate(crypto.FILETYPE_PEM, self)

    def is_signed_by(self, other):
        signature_algorithm = self.get_signature_algorithm()
        self_asn1 = crypto.dump_certificate(
            crypto.FILETYPE_ASN1, self
        )
        self_der = asn1.DerSequence()
        self_der.decode(self_asn1)
        der_cert, der_algo, der_sig = self_der
        der_sig_in = asn1.DerObject()
        der_sig_in.decode(der_sig)
        sig0 = der_sig_in.payload
        if sig0[0] != '\x00':
            raise Exception('Number of unused bits is strange')
        sig = sig0[1:]
        try:
            crypto.verify(other, sig, der_cert, signature_algorithm)
            return True
        except crypto.Error:
            return False
        return False

    def get_subject_string(self):
        return ', '.join(
            '%s=%s' % (x, y) for x, y in self.get_subject().get_components()
        )

    def get_signers(self):
        if self.is_signed_by(self):
            yield None
            return
        for possible_signer in warehouse.get_by_subject(self.get_issuer()):
            if self.is_signed_by(possible_signer):
                yield possible_signer

    def is_self_signed(self):
        return self.is_signed_by(self)

    def is_authority(self):
        for i in range(self.get_extension_count()):
            extension = self.get_extension(i)
            if extension.get_short_name() == 'basicConstraints':
                if str(extension).upper().startswith('CA:FALSE'):
                    return False
                if str(extension).upper().startswith('CA:TRUE'):
                    return True

        if self.get_fingerprint() in [
            '97817950D81C9670CC34D809CF794431367EF474',
            'CE6A64A309E42FBBD9851C453E6409EAE87D60F1',
            '273EE12457FDC4F90C55E82B56167F62F532E547',
            '204285DCF7EB764195578E136BD4B7D1E98E46A5',
            'B3EAC44776C9C81CEAF29D95B6CCA0081B67EC9D',
            '61EF43D77FCAD46151BC98E0C35912AF9FEB6311',
            '742C3192E607E424EB4549542BE1BBC53E6174E2',
            '85371CA6E550143DCE2803471BDE3A09E8F8770F',
            '132D0D45534B6997CDB2D5C339E25576609B5CC6',
            'C8EC8C879269CB4BAB39E98D7E5767F31495739D',
            'A1DB6393916F17E4185509400415C70240B0AE6B',
        ]:
            # known old root certificates without x509v3 extension
            return True
        else:
            return False

    def get_fingerprint(self):
        return self.digest('sha1').replace(':', '')

    def get_chain(self):
        next_in_line = self
        seen = set()
        while True:
            fingerprint = next_in_line.get_fingerprint()
            if fingerprint in seen:
                raise Exception('cycle detected')
            seen.add(fingerprint)

            yield next_in_line

            if next_in_line.is_self_signed():
                return

            issuers = list(next_in_line.get_signers())

            if len(issuers) == 0:
                raise Exception('can not find chain')

            for issuer in issuers:
                if issuer.is_self_signed():
                    next_in_line = issuer
                    break
            else:
                next_in_line = issuers[0]


def _reader(file_handle):
    line = None
    while line != '':
        line = file_handle.readline()
        yield line


def get_pem_strings_from_file_handle(file_handle):
    for pem_strings in get_pem_strings_from_lines(_reader(file_handle)):
        yield pem_strings


def get_pem_strings_from_lines(lines):
    result = []
    for line in lines:
        line = line.strip()
        if len(result) > 0 or line == '-----BEGIN CERTIFICATE-----':
            result.append(line)
        if line == '-----END CERTIFICATE-----':
            yield '\n'.join(result)
            result = []


def get_cert_from_pem_string(input_string):
    input_string = input_string.strip()
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, input_string)
    cert.__class__ = X509Extra
    return cert


def get_certs_from_domain(domain, port):
    if warehouse.was_domain_checked_recently(domain, port):
        raise Exception(
            'domain %s:%d was already scanned recently, try again later'
            % (domain, port)
        )

    process = subprocess.Popen([
        'timeout', '5',
        'openssl', 's_client',
        '-servername', domain,
        '-connect', '%s:%d' % (domain, port),
        '-showcerts',
    ], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate(b'')
    if process.returncode != 0:
        raise Exception('Could not connect to %s:%d' % (domain, port))

    for cert_string in get_pem_strings_from_lines(out.decode().split('\n')):
        yield get_cert_from_pem_string(cert_string)

    warehouse.access_domain(domain, port)
