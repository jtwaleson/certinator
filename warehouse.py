import psycopg2
import logging
import urlparse
import os

import certificate_operations

_database_url = urlparse.urlparse(os.getenv('DATABASE_URL'))
_connection = None


def _get_db_connection():
    global _connection
    if not _connection:
        logging.info('Connecting to database')
        _connection = psycopg2.connect(
            database=_database_url.path[1:],
            user=_database_url.username,
            password=_database_url.password,
            host=_database_url.hostname,
            port=_database_url.port
        )
        _connection.autocommit = True
    return _connection


def store(cert):
    fingerprint = cert.digest('sha1').strip()
    subject_hash = cert.subject_name_hash()
    pem = certificate_operations.get_pem_string_from_cert(cert)

    conn = _get_db_connection()

    with conn.cursor() as cursor:
        logging.debug('going to insert %s', subject_hash)
        try:
            cursor.execute(
                "INSERT INTO certificates (fingerprint, pem, subject_hash) "
                "VALUES (%s, %s, %s);",
                (fingerprint, pem, subject_hash),
            )
        except psycopg2.IntegrityError:
            pass


def get_subject_string(cert):
    return ', '.join('%s=%s' % (x, y) for x, y in cert.get_subject().get_components())


def get_by_subject(subject):
    subject_hash = subject.hash()
    conn = _get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute(
            "SELECT pem FROM certificates WHERE subject_hash = '%s';"
            % subject_hash
        )
        for record in cursor:
            yield certificate_operations.get_cert_from_pem_string(record[0])
