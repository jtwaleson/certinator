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
    '''returns if certificate was actually added'''

    fingerprint = cert.digest('sha1').strip()
    subject_hash = cert.subject_name_hash()
    pem = certificate_operations.get_pem_string_from_cert(cert)

    conn = _get_db_connection()

    with conn.cursor() as cursor:
        logging.debug('attempting to insert %s', fingerprint)
        try:
            cursor.execute(
                "INSERT INTO certificates "
                "(fingerprint, pem, subject_hash, first_seen) "
                "VALUES (%s, %s, %s, now());",
                (fingerprint, pem, subject_hash),
            )
            return True
        except psycopg2.IntegrityError:
            return False


def _get_certs(query, params):
    conn = _get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute(query, params)
        for record in cursor:
            yield certificate_operations.get_cert_from_pem_string(record[0])


def get_by_subject(subject):
    subject_hash = subject.hash()
    for cert in _get_certs(
        "SELECT pem "
        "FROM certificates "
        "WHERE subject_hash = '%s';",
        (subject_hash,)
    ):
        yield cert


def get_most_recent_certificates(limit):
    for cert in _get_certs(
        "SELECT pem FROM certificates "
        "ORDER BY first_seen DESC "
        "LIMIT %s;",
        (limit,)
    ):
        yield cert
