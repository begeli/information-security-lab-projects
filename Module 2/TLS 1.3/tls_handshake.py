#!/usr/bin/env python

'''
tls_handshake.py:
Implementation of the TLS 1.3 Handshake Protocol
'''

from typing import Dict, List, Tuple
from Cryptodome.Random import get_random_bytes
import tls_crypto
import tls_constants
from tls_extensions import (prep_support_vers_ext, prep_support_groups_ext,
                            prep_keyshare_ext, prep_signature_ext)
from tls_error import (StateConfusionError, InvalidMessageStructureError,
                       WrongRoleError)
import tls_extensions


class Handshake:
    "This is the class for the handshake protocol"

    def __init__(self, csuites: List[int], extensions: Dict[int, List[int]], role: int):
        self.csuites = csuites
        self.extensions = extensions
        self.state = tls_constants.INIT_STATE
        self.role = role
        self.csuite = None

        self.master_secret = None
        self.client_hs_traffic_secret = None
        self.server_hs_traffic_secret = None
        self.client_ap_traffic_secret = None
        self.server_ap_traffic_secret = None

        self.ec_sec_keys = {}
        self.ec_sec_key = None
        self.ec_pub_key = None
        self.pub_key = None

        self.server_cert = None
        self.server_cert_string = None

        self.neg_group = None
        self.neg_version = None
        self.signature = None
        self.sid = None
        self.chelo = None
        self.remote_csuites = None
        self.num_remote_csuites = None
        self.remote_extensions = None

        self.transcript = "".encode()
        self.get_random_bytes = get_random_bytes

    def tls_13_compute_server_hs_key_iv(self) -> Tuple[bytes, bytes, int]:
        # FIRST WE NEED TO GENERATE A HANDSHAKE KEY
        if self.server_hs_traffic_secret == None:
            raise StateConfusionError()
        handshake_key, handshake_iv = tls_crypto.tls_derive_key_iv(
            self.csuite, self.server_hs_traffic_secret)
        return handshake_key, handshake_iv, self.csuite

    def tls_13_compute_client_hs_key_iv(self) -> Tuple[bytes, bytes, int]:
        # FIRST WE NEED TO GENERATE A HANDSHAKE KEY
        if self.client_hs_traffic_secret == None:
            raise StateConfusionError()
        handshake_key, handshake_iv = tls_crypto.tls_derive_key_iv(
            self.csuite, self.client_hs_traffic_secret)
        return handshake_key, handshake_iv, self.csuite

    def tls_13_compute_server_ap_key_iv(self) -> Tuple[bytes, bytes, int]:
        # FIRST WE NEED TO GENERATE An APPLICATION KEY
        if self.server_ap_traffic_secret == None:
            raise StateConfusionError()
        application_key, application_iv = tls_crypto.tls_derive_key_iv(
            self.csuite, self.server_ap_traffic_secret)
        return application_key, application_iv, self.csuite

    def tls_13_compute_client_ap_key_iv(self) -> Tuple[bytes, bytes, int]:
        # FIRST WE NEED TO GENERATE AN APPLICATION KEY
        if self.client_ap_traffic_secret == None:
            raise StateConfusionError()
        application_key, application_iv = tls_crypto.tls_derive_key_iv(
            self.csuite, self.client_ap_traffic_secret)
        return application_key, application_iv, self.csuite

    def attach_handshake_header(self, msg_type: int, msg: bytes) -> bytes:
        len_msg = len(msg).to_bytes(3, 'big')
        hs_msg_type = msg_type.to_bytes(1, 'big')
        return hs_msg_type + len_msg + msg

    def process_handshake_header(self, msg_type: int, msg: bytes) -> bytes:
        curr_pos = 0
        curr_msg_type = msg[curr_pos]
        if curr_msg_type != msg_type:
            raise InvalidMessageStructureError()
        curr_pos = curr_pos + tls_constants.MSG_TYPE_LEN
        msg_len = int.from_bytes(
            msg[curr_pos:curr_pos + tls_constants.MSG_LEN_LEN], 'big')
        curr_pos = curr_pos + tls_constants.MSG_LEN_LEN
        ptxt_msg = msg[curr_pos:]
        if msg_len != len(ptxt_msg):
            raise InvalidMessageStructureError()
        return ptxt_msg

    def tls_13_client_hello(self) -> bytes:
        # Set legacy version
        legacy_version = tls_constants.LEGACY_VERSION.to_bytes(tls_constants.MSG_VERS_LEN, byteorder='big')

        # Set random "nonce"
        random = self.get_random_bytes(tls_constants.RANDOM_LEN)

        # Set random session id
        legacy_session_id = self.get_random_bytes(tls_constants.RANDOM_LEN)
        legacy_session_id_len = len(legacy_session_id).to_bytes(tls_constants.SID_LEN_LEN, byteorder='big')
        #self.sid = legacy_session_id # TODO: Might be wrong - check if it is needed

        # Set csuites supported by the client
        csuites = (len(self.csuites) * tls_constants.CSUITE_LEN).to_bytes(tls_constants.CSUITE_LEN_LEN, byteorder='big')
        for suite in self.csuites:
            csuites += suite.to_bytes(tls_constants.CSUITE_LEN, byteorder='big')
        legacy_compression_methods_len = bytes(b'\x01')
        legacy_compression_method = bytes(b'\x00')

        # Set extensions
        support_vers_ext = prep_support_vers_ext(self.extensions)
        support_groups_ext = prep_support_groups_ext(self.extensions)
        keyshare_ext, ec_sec_keys = prep_keyshare_ext(self.extensions)
        self.ec_sec_keys = ec_sec_keys
        signature_ext = prep_signature_ext(self.extensions)
        extensions = support_vers_ext + support_groups_ext + keyshare_ext + signature_ext
        extensions_len = len(extensions).to_bytes(tls_constants.EXT_LEN_LEN, byteorder='big')

        # Combine plaintext fragment
        msg = legacy_version + random + legacy_session_id_len + legacy_session_id + csuites + \
               legacy_compression_methods_len + legacy_compression_method + extensions_len + extensions

        # Attach header to plaintext
        plaintext = self.attach_handshake_header(tls_constants.CHELO_TYPE, msg)

        self.transcript += plaintext
        return plaintext

    def tls_13_process_client_hello(self, chelo_msg: bytes):
        # DECONSTRUCT OUR CLIENTHELLO MESSAGE
        chelo = self.process_handshake_header(
            tls_constants.CHELO_TYPE, chelo_msg)
        curr_pos = 0
        chelo_vers = chelo[curr_pos:curr_pos + tls_constants.MSG_VERS_LEN]
        curr_pos = curr_pos + tls_constants.MSG_VERS_LEN
        chelo_rand = chelo[curr_pos:curr_pos + tls_constants.RANDOM_LEN]
        curr_pos = curr_pos + tls_constants.RANDOM_LEN
        chelo_sess_id_len = chelo[curr_pos]
        curr_pos = curr_pos + tls_constants.SID_LEN_LEN
        self.sid = chelo[curr_pos:curr_pos+chelo_sess_id_len]
        curr_pos = curr_pos+chelo_sess_id_len
        csuites_len = int.from_bytes(
            chelo[curr_pos:curr_pos+tls_constants.CSUITE_LEN_LEN], 'big')
        curr_pos = curr_pos + tls_constants.CSUITE_LEN_LEN
        self.remote_csuites = chelo[curr_pos:curr_pos+csuites_len]
        curr_pos = curr_pos + csuites_len
        self.num_remote_csuites = csuites_len//tls_constants.CSUITE_LEN
        comp_len = int.from_bytes(
            chelo[curr_pos:curr_pos+tls_constants.COMP_LEN_LEN], 'big')
        curr_pos = curr_pos + tls_constants.COMP_LEN_LEN
        legacy_comp = chelo[curr_pos]
        if legacy_comp != 0x00:
            raise InvalidMessageStructureError()
        curr_pos = curr_pos + comp_len
        exts_len = int.from_bytes(
            chelo[curr_pos:curr_pos+tls_constants.EXT_LEN_LEN], 'big')
        curr_pos = curr_pos + tls_constants.EXT_LEN_LEN
        self.remote_extensions = chelo[curr_pos:curr_pos+exts_len]
        self.transcript = self.transcript + chelo_msg

    def tls_13_server_get_remote_extensions(self) -> Dict[str, bytes]:
        curr_ext_pos = 0
        remote_extensions = {}
        while curr_ext_pos < len(self.remote_extensions):
            ext_type = int.from_bytes(
                self.remote_extensions[curr_ext_pos:curr_ext_pos+2], 'big')
            curr_ext_pos = curr_ext_pos + 2
            ext_len = int.from_bytes(
                self.remote_extensions[curr_ext_pos:curr_ext_pos+2], 'big')
            curr_ext_pos = curr_ext_pos + 2
            ext_bytes = self.remote_extensions[curr_ext_pos:curr_ext_pos+ext_len]
            if ext_type == tls_constants.SUPPORT_VERS_TYPE:
                remote_extensions['supported versions'] = ext_bytes
            if ext_type == tls_constants.SUPPORT_GROUPS_TYPE:
                remote_extensions['supported groups'] = ext_bytes
            if ext_type == tls_constants.KEY_SHARE_TYPE:
                remote_extensions['key share'] = ext_bytes
            if ext_type == tls_constants.SIG_ALGS_TYPE:
                remote_extensions['sig algs'] = ext_bytes
            curr_ext_pos = curr_ext_pos + ext_len
        return remote_extensions

    def tls_13_server_select_parameters(self, remote_extensions: Dict[str, bytes]):
        self.neg_version = tls_extensions.negotiate_support_vers_ext(
            self.extensions, remote_extensions['supported versions'])
        self.neg_group = tls_extensions.negotiate_support_group_ext(
            self.extensions, remote_extensions['supported groups'])

        (self.pub_key, self.neg_group, self.ec_pub_key,
         self.ec_sec_key) = tls_extensions.negotiate_keyshare(
            self.extensions, self.neg_group, remote_extensions['key share'])

        self.signature = tls_extensions.negotiate_signature_ext(
            self.extensions, remote_extensions['sig algs'])
        self.csuite = tls_extensions.negotiate_support_csuite(
            self.csuites, self.num_remote_csuites, self.remote_csuites)

    def tls_13_prep_server_hello(self) -> bytes:
        # ALL OF THE LEGACY TLS SERVERHELLO INFORMATION
        # Must be set like this for compatability reasons
        legacy_vers = tls_constants.LEGACY_VERSION.to_bytes(2, 'big')
        # Must be set like this for compatability reasons
        random = get_random_bytes(32)
        legacy_sess_id = self.sid  # Must be set like this for compatability reasons
        legacy_sess_id_len = len(self.sid).to_bytes(1, 'big')
        legacy_compression = (0x00).to_bytes(1, 'big')
        csuite_bytes = self.csuite.to_bytes(2, 'big')
        # WE ATTACH ALL OUR EXTENSIONS
        neg_vers_ext = tls_extensions.finish_support_vers_ext(self.neg_version)
        neg_group_ext = tls_extensions.finish_support_group_ext(self.neg_group)
        supported_keyshare = tls_extensions.finish_keyshare_ext(
            self.pub_key, self.neg_group)
        extensions = neg_vers_ext + neg_group_ext + supported_keyshare
        exten_len = len(extensions).to_bytes(2, 'big')
        msg = legacy_vers + random + legacy_sess_id_len + legacy_sess_id + \
            csuite_bytes + legacy_compression + exten_len + extensions
        shelo_msg = self.attach_handshake_header(tls_constants.SHELO_TYPE, msg)
        self.transcript += shelo_msg
        early_secret = tls_crypto.tls_extract_secret(self.csuite, None, None)
        derived_early_secret = tls_crypto.tls_derive_secret(
            self.csuite, early_secret, "derived".encode(), "".encode())
        ecdh_secret_point = tls_crypto.ec_dh(self.ec_sec_key, self.ec_pub_key)
        ecdh_secret = tls_crypto.point_to_secret(
            ecdh_secret_point, self.neg_group)
        handshake_secret = tls_crypto.tls_extract_secret(
            self.csuite, ecdh_secret, derived_early_secret)
        self.server_hs_traffic_secret = tls_crypto.tls_derive_secret(
            self.csuite, handshake_secret, "s hs traffic".encode(), self.transcript)
        self.client_hs_traffic_secret = tls_crypto.tls_derive_secret(
            self.csuite, handshake_secret, "c hs traffic".encode(), self.transcript)
        derived_hs_secret = tls_crypto.tls_derive_secret(
            self.csuite, handshake_secret, "derived".encode(), "".encode())
        self.master_secret = tls_crypto.tls_extract_secret(
            self.csuite, None, derived_hs_secret)
        return shelo_msg

    def tls_13_process_server_hello(self, shelo_msg: bytes):
        # TODO: Use process_header method here instead
        curr_pos = 0
        curr_msg_type = shelo_msg[curr_pos]
        if curr_msg_type != tls_constants.SHELO_TYPE:
            raise InvalidMessageStructureError

        curr_pos += tls_constants.MSG_TYPE_LEN
        msg_len = int.from_bytes(shelo_msg[curr_pos:curr_pos + tls_constants.MSG_LEN_LEN], 'big')
        if msg_len != len(shelo_msg[curr_pos + tls_constants.MSG_LEN_LEN:]):
            raise InvalidMessageStructureError()

        curr_pos = curr_pos + tls_constants.MSG_LEN_LEN
        legacy_version = shelo_msg[curr_pos:curr_pos + tls_constants.MSG_VERS_LEN]
        if int.from_bytes(legacy_version, byteorder='big') != tls_constants.LEGACY_VERSION:
            raise InvalidMessageStructureError

        curr_pos += tls_constants.MSG_VERS_LEN
        random = shelo_msg[curr_pos:curr_pos + tls_constants.RANDOM_LEN]

        curr_pos += tls_constants.RANDOM_LEN
        shelo_sess_id_len = shelo_msg[curr_pos]

        curr_pos += tls_constants.SID_LEN_LEN
        shelo_sess_id = shelo_msg[curr_pos:curr_pos + shelo_sess_id_len]

        curr_pos += shelo_sess_id_len
        csuite = shelo_msg[curr_pos:curr_pos + tls_constants.CSUITE_LEN]
        self.csuite = int.from_bytes(csuite, byteorder='big')

        curr_pos += tls_constants.CSUITE_LEN
        legacy_compression = shelo_msg[curr_pos]
        if legacy_compression != 0x00:
            raise InvalidMessageStructureError

        curr_pos += tls_constants.COMP_LEN_LEN
        exts_len = int.from_bytes(shelo_msg[curr_pos:curr_pos + tls_constants.EXT_LEN_LEN], 'big')

        curr_pos += tls_constants.EXT_LEN_LEN
        remote_extensions = shelo_msg[curr_pos:]

        if exts_len != len(remote_extensions):
            raise InvalidMessageStructureError

        curr_ext_pos = 0
        # TODO: Should I throw an exception here?
        while (curr_ext_pos < len(remote_extensions)):
            ext_type = int.from_bytes(remote_extensions[curr_ext_pos:curr_ext_pos + 2], 'big')

            curr_ext_pos = curr_ext_pos + 2
            ext_len = int.from_bytes(remote_extensions[curr_ext_pos:curr_ext_pos + 2], 'big')

            curr_ext_pos = curr_ext_pos + 2
            ext_bytes = remote_extensions[curr_ext_pos:curr_ext_pos + ext_len]

            if ext_type == tls_constants.SUPPORT_VERS_TYPE:
                self.neg_version = int.from_bytes(ext_bytes, byteorder='big')
            if ext_type == tls_constants.SUPPORT_GROUPS_TYPE:
                self.neg_group = int.from_bytes(ext_bytes, byteorder='big')
            if ext_type == tls_constants.KEY_SHARE_TYPE:
                name_group = int.from_bytes(ext_bytes[:2], byteorder='big')
                if ext_bytes[4] != 4:
                    raise InvalidMessageStructureError
                pub_key_bytes = ext_bytes[5:]
                ec_pub_key = tls_crypto.convert_x_y_bytes_ec_pub(pub_key_bytes, name_group)
                self.ec_pub_key = ec_pub_key

            curr_ext_pos += ext_len

        self.transcript += shelo_msg

        ec_sec_key = self.ec_sec_keys[name_group]
        shared_secret = tls_crypto.ec_dh(ec_sec_key, ec_pub_key)
        ecdh_secret = tls_crypto.point_to_secret(shared_secret, name_group)

        early_secret = tls_crypto.tls_extract_secret(self.csuite, None, None)
        d_early_secret = \
            tls_crypto.tls_derive_secret(self.csuite, early_secret, "derived".encode(), "".encode())
        handshake_secret = \
            tls_crypto.tls_extract_secret(self.csuite, ecdh_secret, d_early_secret)
        client_hs_traffic_secret = \
            tls_crypto.tls_derive_secret(self.csuite, handshake_secret, "c hs traffic".encode(), self.transcript)
        server_handshake_traffic_secret = \
            tls_crypto.tls_derive_secret(self.csuite, handshake_secret, "s hs traffic".encode(), self.transcript)
        d_handshake_secret = \
            tls_crypto.tls_derive_secret(self.csuite, handshake_secret, "derived".encode(), "".encode())
        master_secret = tls_crypto.tls_extract_secret(self.csuite, None, d_handshake_secret)

        self.early_secret = early_secret
        self.handshake_secret = handshake_secret
        self.client_hs_traffic_secret = client_hs_traffic_secret
        self.server_hs_traffic_secret = server_handshake_traffic_secret
        self.master_secret = master_secret

    def tls_13_server_enc_ext(self):
        msg = 0x0000.to_bytes(2, 'big')
        enc_ext_msg = self.attach_handshake_header(
            tls_constants.ENEXT_TYPE, msg)
        self.transcript = self.transcript + enc_ext_msg
        return enc_ext_msg

    def tls_13_process_enc_ext(self, enc_ext_msg: bytes):
        enc_ext = self.process_handshake_header(
            tls_constants.ENEXT_TYPE, enc_ext_msg)
        if enc_ext != 0x0000.to_bytes(2, 'big'):
            raise InvalidMessageStructureError
        self.transcript = self.transcript + enc_ext_msg

    def tls_13_server_cert(self):
        certificate = tls_constants.SERVER_SUPPORTED_CERTIFICATES[self.signature]
        certificate_bytes = certificate.encode()
        cert_extensions = (0x0000).to_bytes(2, 'big')
        cert_len = (len(certificate_bytes) +
                    len(cert_extensions)).to_bytes(3, 'big')
        cert_chain_len = (len(certificate_bytes) +
                          len(cert_extensions) + len(cert_len)).to_bytes(3, 'big')
        cert_context_len = (0x00).to_bytes(1, 'big')
        msg = cert_context_len + cert_chain_len + \
            cert_len + certificate_bytes + cert_extensions
        cert_msg = self.attach_handshake_header(tls_constants.CERT_TYPE, msg)
        self.transcript = self.transcript + cert_msg
        return cert_msg

    def tls_13_process_server_cert(self, cert_msg: bytes):
        cert = self.process_handshake_header(tls_constants.CERT_TYPE, cert_msg)
        msg_len = len(cert)
        curr_pos = 0
        cert_context_len = cert[curr_pos]
        curr_pos = curr_pos + 1
        if cert_context_len != 0:
            cert_context = cert_msg[curr_pos:curr_pos + cert_context_len]
        curr_pos = curr_pos + cert_context_len
        while curr_pos < msg_len:
            cert_chain_len = int.from_bytes(
                cert[curr_pos: curr_pos + 3], 'big')
            curr_pos = curr_pos + 3
            cert_chain = cert[curr_pos:curr_pos+cert_chain_len]
            curr_chain_pos = 0
            while curr_chain_pos < cert_chain_len:
                cert_len = int.from_bytes(
                    cert_chain[curr_chain_pos: curr_chain_pos + 3], 'big')
                curr_chain_pos = curr_chain_pos + 3
                self.server_cert = cert_chain[curr_chain_pos:curr_chain_pos + cert_len - 2]
                self.server_cert_string = self.server_cert.decode('utf-8')
                # SUBTRACT TWO FOR THE EXTENSIONS, WHICH WILL ALWAYS BE EMPTY
                curr_chain_pos = curr_chain_pos + cert_len
            curr_pos = curr_pos + cert_chain_len
        self.transcript = self.transcript + cert_msg

    def tls_13_server_cert_verify(self) -> bytes:
        transcript_hash = tls_crypto.tls_transcript_hash(
            self.csuite, self.transcript)
        signature = tls_crypto.tls_signature(
            self.signature, transcript_hash, tls_constants.SERVER_FLAG)
        len_sig_bytes = len(signature).to_bytes(2, 'big')
        sig_type_bytes = self.signature.to_bytes(2, 'big')
        msg = sig_type_bytes + len_sig_bytes + signature
        cert_verify_msg = self.attach_handshake_header(
            tls_constants.CVFY_TYPE, msg)
        self.transcript = self.transcript + cert_verify_msg
        return cert_verify_msg

    def tls_13_process_server_cert_verify(self, verify_msg: bytes):
        # Parse the verify message
        processed_verify_msg = self.process_handshake_header(tls_constants.CVFY_TYPE, verify_msg)

        curr_pos = 0
        signature_algorithm = int.from_bytes(processed_verify_msg[:2], byteorder='big')
        curr_pos += 2
        sig_len = int.from_bytes(processed_verify_msg[curr_pos:curr_pos + 2], byteorder='big')
        curr_pos += 2
        sig = processed_verify_msg[curr_pos:]

        if sig_len != len(sig):
            raise InvalidMessageStructureError

        if signature_algorithm in [tls_constants.RSA_PKCS1_SHA256, tls_constants.RSA_PKCS1_SHA384, tls_constants.RSA_PKCS1_SHA512]:
            public_key = tls_crypto.get_rsa_pk_from_cert(self.server_cert_string)
        elif signature_algorithm in [tls_constants.ECDSA_SECP256R1_SHA256, tls_constants.ECDSA_SECP384R1_SHA384, tls_constants.ECDSA_SECP521R1_SHA512]:
            public_key = tls_crypto.get_ecdsa_pk_from_cert(self.server_cert_string)
        else:
            raise InvalidMessageStructureError

        # Hash the transcript
        transcript_hash = tls_crypto.tls_transcript_hash(self.csuite, self.transcript)

        # Verify signature
        tls_crypto.tls_verify_signature(signature_algorithm, transcript_hash, tls_constants.SERVER_FLAG, sig, public_key)

        # Verification succeeded, Update transcript
        self.transcript += verify_msg # TODO: Should this be the processed message?

    def tls_13_finished(self) -> bytes:
        transcript_hash = tls_crypto.tls_transcript_hash(
            self.csuite, self.transcript)
        finished_key = tls_crypto.tls_finished_key_derive(
            self.csuite, self.server_hs_traffic_secret)
        tag = tls_crypto.tls_finished_mac(
            self.csuite, finished_key, transcript_hash)
        fin_msg = self.attach_handshake_header(tls_constants.FINI_TYPE, tag)
        self.transcript = self.transcript + fin_msg
        if self.role == tls_constants.SERVER_FLAG:
            transcript_hash = tls_crypto.tls_transcript_hash(
                self.csuite, self.transcript)
            self.server_ap_traffic_secret = tls_crypto.tls_derive_secret(
                self.csuite, self.master_secret, "s ap traffic".encode(), transcript_hash)
            self.client_ap_traffic_secret = tls_crypto.tls_derive_secret(
                self.csuite, self.master_secret, "c ap traffic".encode(), transcript_hash)
        return fin_msg

    def tls_13_process_finished(self, fin_msg: bytes):
        processed_fin_msg = self.process_handshake_header(tls_constants.FINI_TYPE, fin_msg)

        # Derive Finished Key
        finished_key = tls_crypto.tls_finished_key_derive(self.csuite, self.server_hs_traffic_secret)

        # Hash the transcript
        transcript_hash = tls_crypto.tls_transcript_hash(self.csuite, self.transcript)

        # Verify MAC
        tls_crypto.tls_finished_mac_verify(self.csuite, finished_key, transcript_hash, processed_fin_msg)

        # Update transcript
        self.transcript += fin_msg

        if self.role == tls_constants.CLIENT_FLAG:
            # TODO: Is this where the official bug is?
            transcript_hash = tls_crypto.tls_transcript_hash(self.csuite, self.transcript)
            self.client_ap_traffic_secret = \
                tls_crypto.tls_derive_secret(self.csuite, self.master_secret,  "c ap traffic".encode(), transcript_hash)
            self.server_ap_traffic_secret =\
                tls_crypto.tls_derive_secret(self.csuite, self.master_secret,   "s ap traffic".encode(), transcript_hash)