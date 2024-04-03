import collections
import os
import socket
from datetime import datetime

from cryptography.hazmat.primitives.hashes import SHA256
import constants
from cipher_suites import CIPHER_SUITES, CipherSuite
from packer import pack, prepend_length, record
from reader import read
from print_colors import bcolors

import hashlib
import hmac

def print_hex(b):
    return ':'.join('{:02X}'.format(a) for a in b)


def log(fun):
    def run(*args, **kwargs):
        fun_name = ' '.join(map(lambda x: x[0].upper() + x[1:], fun.__name__.split('_')))
        print(fun_name + ' Begin')
        result = fun(*args, **kwargs)
        print(fun_name + ' End')
        return result

    return run


class Proxy:
    def __init__(self, host, port, tls_version, ciphers, *, extensions=None, match_hostname=True, debug=True,
                 ssl_key_logfile=None):
        self.host = host
        self.port = port
        self.tls_version = tls_version
        self.client_sequence_number = 0
        self.server_sequence_number = 0
        self.security_parameters = dict()
        now = datetime.now()
        self.client_random = int(now.timestamp()).to_bytes(4, 'big') + os.urandom(28)
        self.server_random = None
        self.session_id = b''
        # @todo reuse session_id if possible here
        # self.session_id = bytes.fromhex('bc8f2d2cfb470c8b372d1eb937740dfa51e881d50d03237065b6fcf002513daf')
        ciphers = ciphers if isinstance(ciphers, collections.Iterable) else tuple(ciphers)
        self.ciphers = tuple(CIPHER_SUITES[cipher] for cipher in ciphers if cipher in CIPHER_SUITES)
        self.extensions = extensions
        self.messages = []
        self.cipher_suite: CipherSuite = None
        self.server_certificate = None
        self.match_hostname = match_hostname
        self.http_version = None

        self.conn = socket.create_connection((host, port))
        self.debug = debug
        self.ssl_key_logfile = ssl_key_logfile
        self.is_server_key_exchange = None
        print("proxy init")
        
    def debug_print(self, title, message, *, prefix='\t'):
        if self.debug:
            message = '{color_begin}{message}{color_end}'.format(color_begin=bcolors.OKGREEN, message=message,
                                                                 color_end=bcolors.ENDC)
            print(prefix, title, message)

    def record(self, content_type, data, *, tls_version=None):
        return record(content_type, tls_version or self.tls_version, data)

    def pack(self, header_type, data, *, tls_version=None):
        return pack(header_type, tls_version or self.tls_version, data, len_byte_size=3)

    def read(self, return_record=False):
        record, content = read(self.conn)
        if return_record:
            return record, content
        return content

    @log
    def client_hello(self, message):
        self.conn.send(message)
    
    @log
    def server_hello_1(self):
        record_bytes, hello_bytes = self.read(return_record=True)
        return record_bytes, hello_bytes
    
    @log
    def server_hello_2(self):
        certificate_bytes = self.read()
        return certificate_bytes
    
    @log
    def server_hello_3(self):
        next_bytes = self.read()
        return next_bytes
    
    @log
    def server_hello_4(self):
        hello_done_bytes = self.read()
        return hello_done_bytes
    
    @log
    def client_finish(self, encrypted_data):
        self.conn.send(encrypted_data)

    @log
    def server_finish(self):
        while True:
            record, content = self.read(return_record=True)
            if record[:1] == constants.CONTENT_TYPE_ALERT:
                if content == constants.ERROR_FATAL + constants.ERROR_CODE_BAD_RECORD_MAC:
                    raise Exception('Bad record mac')
                raise Exception(print_hex(content))
            if content[:1] == constants.PROTOCOL_NEW_SESSION_TICKET:
                self.messages.append(content)
                # @todo save session ticket
                pass
            elif record[:1] == constants.PROTOCOL_SERVER_FINISH:
                pass
            elif record[:1] == constants.CONTENT_TYPE_HANDSHAKE:
                return record, content
            

    @log
    def send_application_data(self, encrypted_bytes):
        self.conn.send(encrypted_bytes)

    @log
    def receive_application_data(self):
        while True:
            record, content = self.read(return_record=True)
            if (record is not None and content is not None):
                return record, content

    def generate_aws_signature_v4(self, access_key, secret_key, region, service, date, payload):
        def sign(key, msg):
            return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

        def get_signature_key(key, date_stamp, region_name, service_name):
            k_date = sign(('AWS4' + key).encode('utf-8'), date_stamp)
            k_region = sign(k_date, region_name)
            k_service = sign(k_region, service_name)
            k_signing = sign(k_service, 'aws4_request')
            return k_signing

        algorithm = 'AWS4-HMAC-SHA256'
        canonical_uri = '/'
        canonical_querystring = ''
        canonical_headers = 'content-type:application/x-www-form-urlencoded\nhost:{host}\nx-amz-date:{x_amz_date}\n'.format(
            host='email.' + region + '.amazonaws.com',
            x_amz_date=date.strftime('%Y%m%dT%H%M%SZ')
        )
        signed_headers = 'content-type;host;x-amz-date'
        payload_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
        canonical_request = 'POST\n{uri}\n{query}\n{headers}\n{signed_headers}\n{payload_hash}'.format(
            uri=canonical_uri,
            query=canonical_querystring,
            headers=canonical_headers,
            signed_headers=signed_headers,
            payload_hash=payload_hash
        )
        date_stamp = date.strftime('%Y%m%d')
        credential_scope = '{}/{}/{}/aws4_request'.format(date_stamp, region, service)
        string_to_sign = '{algorithm}\n{x_amz_date}\n{scope}\n{hashed_canonical_request}'.format(
            algorithm=algorithm,
            x_amz_date=date.strftime('%Y%m%dT%H%M%SZ'),
            scope=credential_scope,
            hashed_canonical_request=hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        )
        signing_key = get_signature_key(secret_key, date_stamp, region, service)
        signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()
        authorization_header = '{algorithm} Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}'.format(
            algorithm=algorithm,
            access_key=access_key,
            scope=credential_scope,
            signed_headers=signed_headers,
            signature=signature
        )
        return authorization_header