import collections
import os
from datetime import datetime

import constants
import tls
from certificates import get_certificate, load
from cipher_suites import CIPHER_SUITES, CipherSuite
from packer import pack, prepend_length, record
from print_colors import bcolors
from extensions import Extension, ApplicationLayerProtocolNegotiationExtension as ALPN
from cryptography.hazmat.primitives.hashes import SHA256

import hashlib
import hmac
from dotenv import load_dotenv

load_dotenv()

def custom_print(*args, **kwargs):
    if os.getenv('ENABLE_PRINTS') == 'True':
        print(*args, **kwargs)
              
def print_hex(b):
    return ':'.join('{:02X}'.format(a) for a in b)


def log(fun):
    def run(*args, **kwargs):
        fun_name = ' '.join(map(lambda x: x[0].upper() + x[1:], fun.__name__.split('_')))
        custom_print(fun_name + ' Begin')
        result = fun(*args, **kwargs)
        custom_print(fun_name + ' End')
        return result

    return run


class Client:

    #@log
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

        self.debug = debug
        self.ssl_key_logfile = ssl_key_logfile
        self.is_server_key_exchange = None
        
    def debug_print(self, title, message, *, prefix='\t'):
        if self.debug:
            message = '{color_begin}{message}{color_end}'.format(color_begin=bcolors.OKGREEN, message=message,
                                                                 color_end=bcolors.ENDC)
            custom_print(prefix, title, message)

    def record(self, content_type, data, *, tls_version=None):
        return record(content_type, tls_version or self.tls_version, data)

    def pack(self, header_type, data, *, tls_version=None):
        return pack(header_type, tls_version or self.tls_version, data, len_byte_size=3)

    @log
    def client_hello(self):
        ciphers = b''.join(int(cipher['id'], 16).to_bytes(2, 'big') for cipher in self.ciphers)

        session_id_bytes = prepend_length(self.session_id, len_byte_size=1)

        cipher_suites_bytes = prepend_length(ciphers, len_byte_size=2)

        compression_method_bytes = prepend_length(b'\x00', len_byte_size=1)

        extensions_bytes = prepend_length(b''.join(map(bytes, self.extensions)), len_byte_size=2)

        client_hello_bytes = self.pack(constants.PROTOCOL_CLIENT_HELLO,
                                       self.client_random +
                                       session_id_bytes +
                                       cipher_suites_bytes +
                                       compression_method_bytes +
                                       extensions_bytes
                                       )

        message = self.record(constants.CONTENT_TYPE_HANDSHAKE, client_hello_bytes, tls_version=tls.TLSV1())
        self.messages.append(client_hello_bytes)
        self.debug_print('Host', self.host)
        self.debug_print('Port', self.port)
        self.debug_print('Client random', print_hex(self.client_random))
        self.debug_print('Cipher suite suggested',
                         '{}'.format(', '.join(cipher['openssl_name'] for cipher in self.ciphers)))
        return message

    @log
    def server_hello(self, record_bytes, hello_bytes, certificate_bytes, next_bytes, hello_done_bytes):
        assert record_bytes[:1] == constants.CONTENT_TYPE_HANDSHAKE, 'Server return {}'.format(
            print_hex(record_bytes[:1]))
        self.messages.append(hello_bytes)
        assert len(hello_bytes) > 0, 'No response from server'
        assert hello_bytes[:1] == b'\x02', 'Not server hello'
        tls_version = hello_bytes[4:6]
        assert tls_version == self.tls_version, 'Not a desired tls version'

        # Parse hello bytes
        self.server_random, hello_bytes = hello_bytes[6:6 + 32], hello_bytes[6 + 32:]
        session_id_length = int.from_bytes(hello_bytes[:1], 'big')
        session_id, hello_bytes = hello_bytes[:session_id_length + 1], hello_bytes[session_id_length + 1:]
        # This session_id can be reused for the session_id in the client Hello for the next request
        # Reusing a session_id results in no certificate sent after Server Hello
        server_cipher_suite, hello_bytes = hello_bytes[:2], hello_bytes[2:]
        compression_method, hello_bytes = hello_bytes[:1], hello_bytes[1:]
        extensions_length, hello_bytes = int.from_bytes(hello_bytes[:2], 'big'), hello_bytes[2:]
        extensions = hello_bytes[:extensions_length]
        self.extensions = Extension.parse_extensions(extensions)
        alpn = list(filter(lambda x: isinstance(x, ALPN), self.extensions))
        self.http_version = alpn[0].protocols[0] if len(alpn) > 0 else constants.EXTENSION_ALPN_HTTP_1_1
        assert self.http_version == constants.EXTENSION_ALPN_HTTP_1_1, 'Not support http2 yet'
        cached_cert_path = r'./debug/{}.crt'.format(self.host)
        if certificate_bytes[0] == 0x0B:
            self.messages.append(certificate_bytes)
            certificate_bytes = certificate_bytes[7:]
            os.path.exists(r'./debug') or os.makedirs(r'./debug')
            self.server_certificate = get_certificate(certificate_bytes, open(cached_cert_path, 'wb+'),
                                                      match_hostname=self.match_hostname, host=self.host)
            
            custom_print("certificate", self.server_certificate, "\n")
        elif os.path.exists(cached_cert_path):
            self.server_certificate = load(open(cached_cert_path, 'rb'))
            next_bytes = certificate_bytes
        else:
            raise ValueError('No certificate was received.')

        self.cipher_suite = CipherSuite.get_from_id(self.tls_version, self.client_random, self.server_random,
                                                    self.server_certificate, server_cipher_suite)
        self.messages.append(next_bytes)
        self.is_server_key_exchange = next_bytes[:1] == b'\x0c'
        custom_print("is_server_key_exchange", self.is_server_key_exchange)
        if self.is_server_key_exchange:  # Server key exchange
            self.cipher_suite.parse_key_exchange_params(next_bytes)
            self.messages.append(hello_done_bytes)
        elif self.session_id:  # @todo handle sessions
            raise ValueError('No server key exchange has received. # @todo')
        self.debug_print('Cipher suite negotiated', ' {}({})'.format(self.cipher_suite, print_hex(server_cipher_suite)))
        self.debug_print('TLS version', self.tls_version)
        self.debug_print('Server random', print_hex(self.server_random))
        self.debug_print('Key exchange', self.cipher_suite.key_exchange.__class__.__name__)
        self.debug_print('Server cert not before (UTC)', self.server_certificate.not_valid_before_utc)
        self.debug_print('Server cert not after (UTC)', self.server_certificate.not_valid_after_utc)
        self.debug_print('Server cert fingerprint (sha256)', print_hex(self.server_certificate.fingerprint(SHA256())))
        if self.is_server_key_exchange:
            custom_print("Server Public Key Received")
            public_key = self.cipher_suite.key_exchange.public_key
            self.debug_print('Key Exchange Server Public Key ({!s} bytes)'.format(len(public_key)),
                             print_hex(public_key))
        return None

    @log
    def client_finish(self):
        pre_master_secret, enc_length, encrypted_pre_master_secret = self.cipher_suite.key_exchange.exchange()

        key_exchange_data = constants.PROTOCOL_CLIENT_KEY_EXCHANGE + prepend_length(
            enc_length + encrypted_pre_master_secret, len_byte_size=3)

        key_exchange_bytes = self.record(constants.CONTENT_TYPE_HANDSHAKE, key_exchange_data)
        self.messages.append(key_exchange_data)

        change_cipher_spec_bytes = self.record(constants.PROTOCOL_CHANGE_CIPHER_SPEC, b'\x01')

        self.cipher_suite.pre_master_secret = pre_master_secret

        """
        In SSL/TLS, what is hashed is the handshake messages, i.e. the unencrypted contents. The hash 
        input includes the 4-byte headers for each handshake message (one byte for the message type, 
        three bytes for the message length); however, it does not contain the record headers, or anything 
        related to the record processing (so no padding or MAC). The "ChangeCipherSpec" message (a single 
        byte of value 1) is not a "handshake message" so it is not included in the hash input.
        """
        pre_message = b''.join(self.messages)  # Exclude record layer

        verify_data = self.cipher_suite.sign_verify_data(pre_message)
        verify_bytes = constants.PROTOCOL_CLIENT_FINISH + prepend_length(verify_data, len_byte_size=3)

        kwargs = {
            'content_bytes': verify_bytes,
            'seq_num': self.client_sequence_number,
            'content_type': constants.CONTENT_TYPE_HANDSHAKE
        }
        encrypted_finished = self.cipher_suite.encrypt(**kwargs)
        encrypted_finished_bytes = self.record(constants.CONTENT_TYPE_HANDSHAKE, encrypted_finished)
        self.messages.append(verify_bytes)

        self.client_sequence_number += 1
        if self.is_server_key_exchange:
            self.debug_print('Key Exchange Client Public Key ({!s} bytes)'.format(len(encrypted_pre_master_secret)),
                             print_hex(encrypted_pre_master_secret))
        else:
            self.debug_print('Encrypted pre master secret', print_hex(encrypted_pre_master_secret))
        self.debug_print('Pre master secret', print_hex(pre_master_secret))
        self.debug_print('Master secret', print_hex(self.cipher_suite.keys['master_secret']))
        self.debug_print('Verify data', print_hex(verify_data))

        if self.ssl_key_logfile:
            with open(self.ssl_key_logfile, 'a') as f:
                f.write(f'CLIENT_RANDOM {self.client_random.hex()} {self.cipher_suite.keys["master_secret"].hex()}\n')
        return key_exchange_bytes + change_cipher_spec_bytes + encrypted_finished_bytes

    @log
    def server_finish(self, record, content):
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
            kwargs = {
                'encrypted_bytes': content,
                'seq_num': self.server_sequence_number,
                'content_type': constants.CONTENT_TYPE_HANDSHAKE
            }
            content = self.cipher_suite.decrypt(**kwargs)
            assert content[:1] == constants.PROTOCOL_SERVER_FINISH, ValueError('Not server finished')

            pre_message = b''.join(self.messages)  # Exclude record layer
            verify_data = content[4:]
            self.cipher_suite.verify_verify_data(pre_message, verify_data)
            self.server_sequence_number += 1
        self.debug_print('Verify data', print_hex(verify_data))

    @log
    def send_application_data(self, sender_email, sender_username, sender_password, receiver_email, body):
        access_key = sender_username
        secret_key = sender_password
        region = 'us-east-2'
        sender = sender_email
        subject = 'Test Email'
        body = body
        recipient = receiver_email
        date = datetime.utcnow()

        payload = (
            "Action=SendEmail"
            "&Source={sender}"
            "&Destination.ToAddresses.member.1={recipient}"
            "&Message.Subject.Data={subject}"
            "&Message.Body.Text.Data={body}"
        ).format(
            sender=sender,
            recipient=recipient,
            subject=subject,
            body=body
        )
        
        data = 'POST https://email.us-east-2.amazonaws.com/ HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nX-Amz-Date: {date}\r\nAuthorization: {authorization}\r\nContent-Length: {content_length}\r\n\r\n{payload}'.format(
            host=self.host,
            date=date.strftime('%Y%m%dT%H%M%SZ'),
            authorization=self.generate_aws_signature_v4(access_key, secret_key, region, 'ses', date, payload),
            payload=payload,
            content_length=str(len(payload)),
        )
        
        custom_print(data)
        
        kwargs = {
            'content_bytes': data.encode(),
            'seq_num': self.client_sequence_number,
            'content_type': constants.CONTENT_TYPE_DATA
        }
        
        
        encrypted_data = self.cipher_suite.encrypt(**kwargs)
        encrypted_bytes = self.record(constants.CONTENT_TYPE_DATA, encrypted_data)
        self.client_sequence_number += 1
        self.debug_print('Plain', data.replace('\r', '\\r').replace('\n', '\\n'))
        self.debug_print('Encrypted', print_hex(encrypted_bytes))
        
        return encrypted_bytes

    @log
    def receive_application_data(self, record, content):
        result = b''
        content_length = None
        if record[:3] == constants.CONTENT_TYPE_ALERT + self.tls_version or len(content) == 0:
            return
        kwargs = {
            'encrypted_bytes': content,
            'seq_num': self.server_sequence_number,
            'content_type': constants.CONTENT_TYPE_DATA
        }

        decoded = self.cipher_suite.decrypt(**kwargs)
        result += decoded
        custom_print("received application data")
        custom_print(result)
        return result
    
        if content_length is None:
            tmp = result.split(b'\r\n\r\n')[0]
            pos = tmp.find(b'Content-Length')
            if pos > -1:
                content_length = int(decoded[pos + 15:tmp.find(b'\r\n', pos)])

            if result[-4:] == b'\r\n\r\n':
                return

            if content_length is not None and len(result) >= content_length:
                return
            self.server_sequence_number += 1
        
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