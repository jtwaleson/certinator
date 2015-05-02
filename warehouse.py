import boto
import logging
import os
import redis
import json

import certificate_operations

_bucket = None


def _get_bucket():
    global _bucket
    if not _bucket:
        logging.info('Connecting to database')
        connection = boto.connect_s3(
            aws_access_key_id=os.environ['S3_ACCESS_KEY_ID'],
            aws_secret_access_key=os.environ['S3_SECRET_ACCESS_KEY'],
        )
        _bucket = connection.get_bucket('all-certificates')
    return _bucket


_redis = None


def _get_redis():
    global _redis
    if not _redis:
        logging.info('Connecting to redis')
        credentials = json.loads(
            os.environ['VCAP_SERVICES']
        )['rediscloud'][0]['credentials']
        _redis = redis.Redis(
            host=credentials['hostname'],
            port=int(credentials['port']),
            password=credentials['password'],
        )
    return _redis


def store(cert):
    '''returns if certificate was actually added'''

    fingerprint = cert.digest('sha1').strip().replace(':', '')
    subject_hash = cert.subject_name_hash()
    pem = certificate_operations.get_pem_string_from_cert(cert)

    if _get_redis().exists(fingerprint):
        return False

    bucket = _get_bucket()
    if bucket.get_key('certs/%s' % fingerprint):
        return False

    certificate_key = bucket.new_key(
        'certs/%s' % fingerprint
    )
    certificate_key.content_type = 'application/x-pem-file'
    certificate_key.set_metadata(
        'Cache-Control', 'max-age=%d, public' % (3600 * 24 * 365 * 10),
    )
    certificate_key.set_metadata(
        'X-Subject-Hash', str(subject_hash),
    )
    certificate_key.set_contents_from_string(pem, replace=True)
    bucket.new_key(
        'subjects/%s/%s' % (subject_hash, fingerprint)
    ).set_contents_from_string('')
    _get_redis().setex(fingerprint, pem, 60 * 30)
    return True


def get_by_fingerprint(fingerprint):
    fingerprint = fingerprint.replace(':', '')
    bucket = _get_bucket()
    contents = bucket.get_key('certs/%s' % fingerprint).get_contents_as_string()
    return certificate_operations.get_cert_from_pem_string(contents)


def get_by_subject(subject):
    subject_hash = subject.hash()
    bucket = _get_bucket()

    print('getting list %s' % subject_hash)
    for key in bucket.list(prefix='subjects/%s' % subject_hash):
        yield get_by_fingerprint(key.name.split('/')[2])


def was_domain_checked_recently(domain, port):
    return _get_redis().exists('%s:%d' % (domain, port))


def access_domain(domain, port):
    return _get_redis().setex('%s:%d' % (domain, port), '', 60 * 10)
