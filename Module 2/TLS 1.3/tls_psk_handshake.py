#!/usr/bin/env python

'''
tls_psk_handshake.py:
A series of functions implementing aspects of TLS 1.3 PSK functionality
'''

import pickle
from io import open
import time
from typing import Dict, List, Tuple, Union
from Cryptodome.Cipher import AES, ChaCha20_Poly1305
from Cryptodome.Hash import HMAC, SHA256, SHA384
from Cryptodome.Random import get_random_bytes
import tls_crypto
import tls_constants
from tls_error import *
import tls_extensions
from tls_handshake import Handshake

generate_client_test = False
generate_server_test = False
generate_server_random_test = False


def timer() -> int:
    return int(time.time()*1000)


class PSKHandshake(Handshake):
    "This is the class for aspects of the handshake protocol"

    __rand_id = 0

    def __init__(self, csuites: List[int], extensions: Dict[int, List[int]], role: int,
                 psks: List[Dict[str, Union[bytes, int]]] = None, psk_modes: List[int] = None,
                 server_static_enc_key: bytes = None, early_data: bytes = None):
        super().__init__(csuites, extensions, role)
        self.psks = psks
        self.psk = None
        self.psk_modes = psk_modes
        self.server_static_enc_key = server_static_enc_key
        self.early_data = early_data
        self.client_early_traffic_secret = None
        self.accept_early_data = False
        self.selected_identity = None
        self.resumption_master_secret = None
        self.max_early_data = None
        self.offered_psks = None
        self.use_keyshare = None
        self.client_early_data = None
        self.get_time = timer
        self.get_random_bytes = get_random_bytes

    def tls_derive_PSK(self, ticket_nonce) -> bytes:
        hkdf = tls_crypto.HKDF(self.csuite)
        hash_length = tls_constants.SHA_384_LEN if self.csuite == tls_constants.TLS_AES_256_GCM_SHA384 else tls_constants.SHA_256_LEN
        label = tls_crypto.tls_hkdf_label("resumption".encode(), ticket_nonce, hash_length)
        PSK = hkdf.tls_hkdf_expand(self.resumption_master_secret, label, hash_length)

        return PSK

    def tls_psk_aead_encrypt(self, key, nonce, plaintext):
        # Create the cipher
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)

        # Encrypt the plaintext
        ctxt, tag = cipher.encrypt_and_digest(plaintext)

        return ctxt + tag

    def tls_13_server_new_session_ticket(self) -> bytes:
        LIFETIME = 604800
        ticket_lifetime = LIFETIME.to_bytes(4, byteorder='big')
        ticket_age_add = self.get_random_bytes(4)
        ticket_nonce = self.get_random_bytes(8)
        ticket_nonce_len = len(ticket_nonce).to_bytes(1, byteorder='big')

        MAX_DATA_SIZE = 2 ** 12
        early_data_indication = self.tls_13_early_data_ext(MAX_DATA_SIZE.to_bytes(4, byteorder='big'))
        ext_len = len(early_data_indication).to_bytes(2, byteorder='big')

        PSK = self.tls_derive_PSK(ticket_nonce)
        ptxt = PSK + ticket_age_add + ticket_lifetime + (self.csuite).to_bytes(2, byteorder='big')
        ctxt = self.tls_psk_aead_encrypt(self.server_static_enc_key, ticket_nonce, ptxt)
        ticket = ticket_nonce + ctxt
        ticket_len = len(ticket).to_bytes(2, byteorder='big')

        new_sess_ticket = ticket_lifetime + ticket_age_add + ticket_nonce_len + ticket_nonce + \
               ticket_len + ticket + ext_len + early_data_indication
        processed_sess_ticket = self.attach_handshake_header(tls_constants.NEWST_TYPE, new_sess_ticket)

        return processed_sess_ticket

    def tls_13_client_parse_new_session_ticket(self, nst_msg: bytes) -> Dict[str, Union[bytes, int]]:
        LIFETIME = 604800
        arrival = self.get_time()

        # Parse the message
        processed_nst_msg = self.process_handshake_header(tls_constants.NEWST_TYPE, nst_msg)

        curr_pos = 0
        lifetime = int.from_bytes(processed_nst_msg[:4], byteorder='big')
        # TODO: This might be wrong - Are we guaranteed that lifetime is this?
        #if lifetime != LIFETIME:
        #    raise InvalidMessageStructureError

        curr_pos += 4
        lifetime_add = int.from_bytes(processed_nst_msg[curr_pos:curr_pos + 4], byteorder='big')
        curr_pos += 4
        ticket_nonce_len = processed_nst_msg[curr_pos]
        curr_pos += 1
        ticket_nonce = processed_nst_msg[curr_pos:curr_pos + ticket_nonce_len]
        PSK = self.tls_derive_PSK(ticket_nonce)

        curr_pos += ticket_nonce_len
        ticket_len = int.from_bytes(processed_nst_msg[curr_pos:curr_pos + 2], byteorder='big')
        curr_pos += 2
        ticket = processed_nst_msg[curr_pos:curr_pos + ticket_len]

        curr_pos += ticket_len
        ext_len = processed_nst_msg[curr_pos:curr_pos + 2]
        curr_pos += 2
        ext = processed_nst_msg[curr_pos:]
        ext_type = int.from_bytes(ext[:2], byteorder='big')
        if ext_type != tls_constants.EARLY_DATA_TYPE:
            raise InvalidMessageStructureError

        ext_data_len = int.from_bytes(ext[2:2 + tls_constants.EXT_LEN_LEN], byteorder='big')
        ext_data = ext[2 + tls_constants.EXT_LEN_LEN:]
        if ext_data_len != len(ext_data):
            raise InvalidMessageStructureError
        max_data = int.from_bytes(ext_data, byteorder='big')

        #early_secret = tls_crypto.tls_extract_secret(self.csuite, PSK, None)
        #binder_key = \
        #    tls_crypto.tls_derive_secret(self.csuite, early_secret, "res binder".encode(), "".encode())

        binder_key = self.tls_13_generate_binder_key(self.csuite, PSK)

        PSK_dict = {}
        PSK_dict["PSK"] = PSK
        PSK_dict["lifetime"] = lifetime
        PSK_dict["lifetime_add"] = lifetime_add
        PSK_dict["ticket"] = ticket
        PSK_dict["max_data"] = max_data
        PSK_dict["binder key"] = binder_key
        PSK_dict["csuite"] = self.csuite
        PSK_dict["arrival"] = arrival

        return PSK_dict

    def tls_13_generate_binder_key(self, csuite, PSK):
        early_secret = tls_crypto.tls_extract_secret(csuite, PSK, None)
        binder_key = \
            tls_crypto.tls_derive_secret(csuite, early_secret, "res binder".encode(), "".encode())

        return binder_key

    def tls_13_client_prep_psk_mode_extension(self) -> bytes:
        psk_kex_mode = "".encode()
        for mode in self.psk_modes:
            psk_kex_mode += mode.to_bytes(1, byteorder='big')

        data_len = len(psk_kex_mode).to_bytes(1, byteorder='big')
        ext_type = tls_constants.PSK_KEX_MODE_TYPE.to_bytes(2, byteorder='big')
        ext_len = len(data_len + psk_kex_mode).to_bytes(2, byteorder='big')

        return ext_type + ext_len + data_len + psk_kex_mode

    def tls_13_create_psk_identity(self, PSK_dict: Dict[str, Union[bytes, int]], enter_time: int) -> bytes:
        arrival = PSK_dict["arrival"]
        lifetime_add = PSK_dict["lifetime_add"]
        ticket_age = enter_time - arrival
        obfuscated_ticket_age = (ticket_age + lifetime_add) % 2**32

        identity = PSK_dict["ticket"]
        identity_len = len(identity).to_bytes(2, byteorder='big')
        obfuscated_ticket_age_bytes = obfuscated_ticket_age.to_bytes(4, byteorder='big')

        return identity_len + identity + obfuscated_ticket_age_bytes

    def tls_13_compute_expected_binder_len(self) -> Tuple[int, bytes]:
        len = 0

        for psk in self.psks:
            if psk["csuite"] in [tls_constants.TLS_AES_128_GCM_SHA256, tls_constants.TLS_CHACHA20_POLY1305_SHA256]:
                len += SHA256.digest_size + 1
            elif psk["csuite"] == tls_constants.TLS_AES_256_GCM_SHA384:
                len += SHA384.digest_size + 1

        return len, len.to_bytes(2, byteorder='big')

    def tls_13_create_psk_binder(self, PSK_dict: Dict[str, Union[bytes, int]], msg: bytes) -> bytes:
        transcript_hash = tls_crypto.tls_transcript_hash(PSK_dict["csuite"], msg)
        key = tls_crypto.tls_finished_key_derive(PSK_dict["csuite"], PSK_dict["binder key"])
        binder = tls_crypto.tls_finished_mac(PSK_dict["csuite"], key, transcript_hash)
        binder_len = len(binder).to_bytes(1, byteorder='big')

        return binder_len + binder

    def tls_13_client_add_psk_extension(self, chelo: bytes, extensions: bytes) -> Tuple[bytes, List[Dict[str, Union[bytes, int]]]]:
        valid_psks = []
        enter_time = self.get_time()

        # Compute identities field
        identities = "".encode()
        for psk in self.psks:
            if psk["lifetime"] * 1000 < enter_time - psk["arrival"]:
                continue
            identities += self.tls_13_create_psk_identity(psk, enter_time)
            valid_psks.append(psk)

        identities_len = len(identities).to_bytes(2, byteorder='big')

        # Compute expected binder length
        binder_len, binder_len_bytes = self.tls_13_compute_expected_binder_len()

        # Compute psk extension meta data
        psk_ext_type = tls_constants.PSK_TYPE.to_bytes(2, byteorder='big')
        psk_ext_len = len(identities) + 2 + binder_len + 2 # + 2 for identities and binder length bits
        psk_ext_len_bytes = psk_ext_len.to_bytes(2, byteorder='big')

        # Calculate the total extension length
        ext_len = len(extensions) + 2 + 2 + psk_ext_len # + 2 for psk extension type and length
        ext_len_bytes = ext_len.to_bytes(2, byteorder='big')

        # Create the header for the client hello
        msg_type = tls_constants.CHELO_TYPE.to_bytes(1, byteorder='big')
        msg_len = len(chelo) + 2 + ext_len
        msg_len_bytes = msg_len.to_bytes(3, byteorder='big')

        # Create the partial client hello message
        msg = msg_type + msg_len_bytes + chelo + ext_len_bytes + extensions \
              + psk_ext_type + psk_ext_len_bytes + identities_len + identities

        binders = "".encode()
        for psk in valid_psks:
            binders += self.tls_13_create_psk_binder(psk, msg)

        # Create the full psk extension
        psk_ext = psk_ext_type + psk_ext_len_bytes + identities_len + identities + binder_len_bytes + binders

        return psk_ext, valid_psks

    def tls_aead_decrypt(self, key, nonce, ciphertext):
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)

        # Decrypty and Verify the ciphertext
        ctxt_length = len(ciphertext) - tls_constants.MAC_LEN[tls_constants.TLS_CHACHA20_POLY1305_SHA256]
        ctxt = ciphertext[0:ctxt_length]
        tag = ciphertext[ctxt_length:]
        plaintext = cipher.decrypt_and_verify(ctxt, tag)

        return plaintext

    def tls_13_parse_identities(self, identities: bytes):
        identities_list = []

        curr_pos = 0
        while curr_pos < len(identities):
            identity_len = int.from_bytes(identities[curr_pos:curr_pos + 2], byteorder='big')
            curr_pos += 2
            identity = identities[curr_pos:curr_pos + identity_len]
            curr_pos += identity_len
            obfuscated_ticket_age = int.from_bytes(identities[curr_pos:curr_pos + 4], byteorder='big')
            curr_pos += 4

            ticket_nonce = identity[:8]
            ctxt = identity[8:]
            ptxt = self.tls_aead_decrypt(self.server_static_enc_key, ticket_nonce, ctxt)
            ptxt_pos = 0
            ptxt_len = len(ptxt)
            PSK = ptxt[ptxt_pos:ptxt_pos + ptxt_len - 10]
            ptxt_pos += ptxt_len - 10
            ticket_add_age = int.from_bytes(ptxt[ptxt_pos:ptxt_pos + 4], byteorder='big')
            ptxt_pos += 4
            ticket_lifetime = int.from_bytes(ptxt[ptxt_pos:ptxt_pos + 4], byteorder='big')
            ptxt_pos += 4
            csuite = int.from_bytes(ptxt[ptxt_pos:], byteorder='big')
            identities_list.append((PSK, ticket_add_age, ticket_lifetime, csuite, obfuscated_ticket_age))

        return identities_list

    def tls_13_parse_binders(self, binders):
        binders_list = []

        curr_pos = 0
        while curr_pos < len(binders):
            binder_len = binders[curr_pos]
            curr_pos += 1
            binder = binders[curr_pos:curr_pos + binder_len]
            curr_pos += binder_len
            binders_list.append(binder)

        return binders_list

    def tls_13_server_parse_psk_extension(self, psk_extension: bytes) -> Tuple[bytes, int]:
        curr_pos = 0
        identities_len = int.from_bytes(psk_extension[curr_pos:curr_pos + 2], byteorder='big')

        curr_pos += 2
        identities = psk_extension[curr_pos:curr_pos + identities_len]
        identities_list = self.tls_13_parse_identities(identities)

        curr_pos += identities_len
        binders_len = int.from_bytes(psk_extension[curr_pos:curr_pos + 2], byteorder='big')

        curr_pos += 2
        binders = psk_extension[curr_pos:]
        binders_list = self.tls_13_parse_binders(binders)

        index = 0
        transcript_len = len(self.transcript)
        msg = self.transcript[:transcript_len - (binders_len + 2)]
        for identity in identities_list:
            ticket_age = (identity[4] - identity[1]) % 2**32
            # Check is PSK is still valid
            if ticket_age > identity[2] * 1000:
                index += 1
                continue

            # Check if PSK was generated with the negotiated cipher suite
            if identity[3] != self.csuite:
                raise VerificationFailure

            # Verify Binder
            binder_key = self.tls_13_generate_binder_key(identity[3], identity[0])
            transcript_hash = tls_crypto.tls_transcript_hash(identity[3], msg)
            key = tls_crypto.tls_finished_key_derive(identity[3], binder_key)
            binder = tls_crypto.tls_finished_mac(identity[3], key, transcript_hash)

            if binders_list[index] != binder:
                raise BinderVerificationError

            return identity[0], index

        raise TLSError

    def tls_13_client_hello(self) -> bytes:
        # Set legacy version
        legacy_version = tls_constants.LEGACY_VERSION.to_bytes(tls_constants.MSG_VERS_LEN, byteorder='big')

        # Set random "nonce"
        random = self.get_random_bytes(tls_constants.RANDOM_LEN)

        # Set random session id
        legacy_session_id = self.get_random_bytes(tls_constants.RANDOM_LEN)
        legacy_session_id_len = len(legacy_session_id).to_bytes(tls_constants.SID_LEN_LEN, byteorder='big')

        # Set csuites supported by the client
        csuites = (len(self.csuites) * tls_constants.CSUITE_LEN).to_bytes(tls_constants.CSUITE_LEN_LEN, byteorder='big')
        for suite in self.csuites:
            csuites += suite.to_bytes(tls_constants.CSUITE_LEN, byteorder='big')
        legacy_compression_methods_len = bytes(b'\x01')
        legacy_compression_method = bytes(b'\x00')

        chelo_prefix = legacy_version + random + legacy_session_id_len + legacy_session_id + csuites + \
              legacy_compression_methods_len + legacy_compression_method

        # Set extensions
        support_vers_ext = tls_extensions.prep_support_vers_ext(self.extensions)
        support_groups_ext = tls_extensions.prep_support_groups_ext(self.extensions)
        keyshare_ext, ec_sec_keys = tls_extensions.prep_keyshare_ext(self.extensions)
        self.ec_sec_keys = ec_sec_keys
        signature_ext = tls_extensions.prep_signature_ext(self.extensions)
        extensions = support_vers_ext + support_groups_ext + keyshare_ext + signature_ext

        # TODO: Added for early data part
        if self.early_data:
            early_data_indication_ext = self.tls_13_early_data_ext()
            extensions += early_data_indication_ext

        if self.psks:#self.psks is not None and len(self.psks) > 0:
            psk_mode_ext = self.tls_13_client_prep_psk_mode_extension()
            extensions += psk_mode_ext
            psk_ext, self.psks = self.tls_13_client_add_psk_extension(chelo_prefix, extensions)
            extensions += psk_ext

        extensions_len = len(extensions).to_bytes(tls_constants.EXT_LEN_LEN, byteorder='big')

        # Combine plaintext fragment
        msg = chelo_prefix + extensions_len + extensions

        # Attach header to plaintext
        plaintext = self.attach_handshake_header(tls_constants.CHELO_TYPE, msg)

        self.transcript += plaintext

        # Set client early traffic
        if self.early_data:
            PSK = self.psks[0]['PSK']
            # Very sketchy, does this work properly?
            self.csuite = self.psks[0]['csuite']
            early_secret = tls_crypto.tls_extract_secret(self.csuite, PSK, None)
            self.client_early_traffic_secret = \
                tls_crypto.tls_derive_secret(self.csuite, early_secret, "c e traffic".encode(), self.transcript)

        return plaintext

    def tls_13_compute_client_early_key_iv(self) -> Tuple[bytes, bytes, int]:
        # FIRST WE NEED TO GENERATE A HANDSHAKE KEY
        if self.client_early_traffic_secret is None:
            raise StateConfusionError()
        early_data_key, early_data_iv = tls_crypto.tls_derive_key_iv(
            self.csuite, self.client_early_traffic_secret)
        return early_data_key, early_data_iv, self.csuite

    def tls_13_eoed(self) -> bytes:
        return self.attach_handshake_header(tls_constants.EOED_TYPE, b'')

    def tls_13_finished(self) -> bytes:
        fin_msg = super().tls_13_finished()

        # Set resumption secret master
        if self.role == tls_constants.CLIENT_FLAG:
            transcript_hash = self.transcript  # tls_crypto.tls_transcript_hash(self.csuite, self.transcript)
            self.resumption_master_secret = \
                tls_crypto.tls_derive_secret(self.csuite, self.master_secret, "res master".encode(), transcript_hash)

        return fin_msg

    def tls_13_process_finished(self, fin_msg: bytes):
        super().tls_13_process_finished(fin_msg)

        # Set resumption secret master
        if self.role == tls_constants.SERVER_FLAG:
            transcript_hash = self.transcript  # tls_crypto.tls_transcript_hash(self.csuite, self.transcript)
            self.resumption_master_secret = \
                tls_crypto.tls_derive_secret(self.csuite, self.master_secret, "res master".encode(), transcript_hash)

    def tls_13_early_data_ext(self, data: bytes = b'') -> bytes:
        ext_type = tls_constants.EARLY_DATA_TYPE.to_bytes(2, byteorder='big')
        ext_data_len = len(data).to_bytes(2, byteorder='big')

        return ext_type + ext_data_len + data

    def tls_13_server_enc_ext(self) -> bytes:
        # If we are not receiving early data
        if not self.accept_early_data:
            return super().tls_13_server_enc_ext()

        ext_data = self.tls_13_early_data_ext()
        enc_ext_msg = self.attach_handshake_header(tls_constants.ENEXT_TYPE, ext_data)
        self.transcript += enc_ext_msg

        return enc_ext_msg
        
    def tls_13_process_enc_ext(self, enc_ext_msg: bytes):
        # If we are not sending early data
        if self.early_data is None:
            super().tls_13_process_enc_ext(enc_ext_msg)
            return

        enc_ext = self.process_handshake_header(
            tls_constants.ENEXT_TYPE, enc_ext_msg)
        if enc_ext != self.tls_13_early_data_ext():
            raise InvalidMessageStructureError
        self.transcript += enc_ext_msg
        
    def tls_13_server_get_remote_extensions(self) -> Dict[str, bytes]:
        curr_ext_pos = 0
        remote_extensions = {}
        while curr_ext_pos < len(self.remote_extensions):
            ext_type = int.from_bytes(
                self.remote_extensions[curr_ext_pos:curr_ext_pos + 2], 'big')
            curr_ext_pos = curr_ext_pos + 2
            ext_len = int.from_bytes(
                self.remote_extensions[curr_ext_pos:curr_ext_pos + 2], 'big')
            curr_ext_pos = curr_ext_pos + 2
            ext_bytes = self.remote_extensions[curr_ext_pos:curr_ext_pos + ext_len]
            if ext_type == tls_constants.SUPPORT_VERS_TYPE:
                remote_extensions['supported versions'] = ext_bytes
            if ext_type == tls_constants.SUPPORT_GROUPS_TYPE:
                remote_extensions['supported groups'] = ext_bytes
            if ext_type == tls_constants.KEY_SHARE_TYPE:
                remote_extensions['key share'] = ext_bytes
            if ext_type == tls_constants.SIG_ALGS_TYPE:
                remote_extensions['sig algs'] = ext_bytes
            if ext_type == tls_constants.EARLY_DATA_TYPE:
                remote_extensions['early data'] = ext_bytes
            if ext_type == tls_constants.PSK_TYPE:
                remote_extensions['psk'] = ext_bytes
            if ext_type == tls_constants.PSK_KEX_MODE_TYPE:
                remote_extensions['psk mode'] = ext_bytes
            curr_ext_pos = curr_ext_pos + ext_len
        return remote_extensions
        
    def tls_13_server_parse_psk_mode_ext(self, modes_bytes: bytes) -> bytes:
        modes_len = modes_bytes[0]
        modes = modes_bytes[1:modes_len+1]
        return modes

    def tls_13_find_supported_psk_modes(self, psk_modes: bytes):
        support_psk_ke = False
        support_psk_dhe_ke = False

        curr_pos = 0
        supported_mode_len = psk_modes[curr_pos]
        curr_pos += 1
        # Parse and set the supported PSK modes
        for i in range(supported_mode_len):
            mode = psk_modes[curr_pos]
            if mode == tls_constants.PSK_KE_MODE:
                support_psk_ke = True
            if mode == tls_constants.PSK_DHE_KE_MODE:
                support_psk_dhe_ke = True

        return support_psk_ke, support_psk_dhe_ke

    def tls_13_server_select_parameters(self, remote_extensions: Dict[str, bytes]):
        """This method sets the following fields to indicate the selected parameters:
            self.use_keyshare # check
            self.client_early_data
            self.neg_version # check
            self.csuite # check
            self.psk # check
            self.selected_identity # check
            self.use_keyshare # check
            self.client_early_data
            self.accept_early_data # check, i guess
            self.neg_group # check
            self.pub_key # check
            self.ec_pub_key, # check
            self.ec_sec_key # check
            self.signature # check
        """
        self.neg_version = tls_extensions.negotiate_support_vers_ext(
            self.extensions, remote_extensions['supported versions'])
        self.neg_group = tls_extensions.negotiate_support_group_ext(
            self.extensions, remote_extensions['supported groups'])

        self.signature = tls_extensions.negotiate_signature_ext(
            self.extensions, remote_extensions['sig algs'])
        self.csuite = tls_extensions.negotiate_support_csuite(
            self.csuites, self.num_remote_csuites, self.remote_csuites)

        support_psk_ke = False
        support_psk_dhe_ke = False
        if 'psk mode' in remote_extensions:
            support_psk_ke, support_psk_dhe_ke = \
                self.tls_13_find_supported_psk_modes(remote_extensions['psk mode'])

        # Based on our PSK mode set server parameters
        if support_psk_dhe_ke:
            self.psk, self.selected_identity = \
                self.tls_13_server_parse_psk_extension(remote_extensions['psk'])
            self.accept_early_data = ('early data' in remote_extensions) and (self.selected_identity == 0)
            if 'key share' in remote_extensions:
                (self.pub_key, self.neg_group, self.ec_pub_key,
                 self.ec_sec_key) = tls_extensions.negotiate_keyshare(
                    self.extensions, self.neg_group, remote_extensions['key share'])
                self.use_keyshare = True
        elif support_psk_ke:
            self.psk, self.selected_identity = \
                self.tls_13_server_parse_psk_extension(remote_extensions['psk'])
            self.accept_early_data = ('early data' in remote_extensions) and (self.selected_identity == 0)
        else:
            if 'key share' in remote_extensions:
                (self.pub_key, self.neg_group, self.ec_pub_key,
                 self.ec_sec_key) = tls_extensions.negotiate_keyshare(
                    self.extensions, self.neg_group, remote_extensions['key share'])
                self.use_keyshare = True

    def tls_13_get_server_psk_ext(self):
        ext_type = tls_constants.PSK_TYPE.to_bytes(2, byteorder='big')
        ext_len = (4).to_bytes(2, byteorder='big')
        ext_data = self.selected_identity.to_bytes(4, byteorder='big')

        return ext_type + ext_len + ext_data

    def tls_13_prep_server_hello(self) -> bytes:
        """ Creates the Server Hello message, updates the transcript, and sets the following fields:
            self.client_early_secret
            self.server_hs_traffic_secret
            self.client_hs_traffic_secret
            self.master_secret
        """
        # ALL OF THE LEGACY TLS SERVERHELLO INFORMATION
        # Must be set like this for compatability reasons
        legacy_vers = tls_constants.LEGACY_VERSION.to_bytes(2, 'big')
        # Must be set like this for compatability reasons
        random = self.get_random_bytes(32)
        legacy_sess_id = self.sid  # Must be set like this for compatability reasons
        legacy_sess_id_len = len(self.sid).to_bytes(1, 'big')
        legacy_compression = (0x00).to_bytes(1, 'big')
        csuite_bytes = self.csuite.to_bytes(2, 'big')
        # WE ATTACH ALL OUR EXTENSIONS
        neg_vers_ext = tls_extensions.finish_support_vers_ext(self.neg_version)
        neg_group_ext = tls_extensions.finish_support_group_ext(self.neg_group)

        supported_keyshare = "".encode()
        if self.use_keyshare:
            supported_keyshare = tls_extensions.finish_keyshare_ext(
                self.pub_key, self.neg_group)

        psk_ext = "".encode()
        if self.psk is not None:
            psk_ext = self.tls_13_get_server_psk_ext()

        extensions = neg_vers_ext + neg_group_ext + supported_keyshare + psk_ext
        exten_len = len(extensions).to_bytes(2, 'big')

        msg = legacy_vers + random + legacy_sess_id_len + legacy_sess_id + \
              csuite_bytes + legacy_compression + exten_len + extensions
        shelo_msg = self.attach_handshake_header(tls_constants.SHELO_TYPE, msg)

        # Set secrets
        ecdh_secret = None
        if self.use_keyshare:
            ecdh_secret_point = tls_crypto.ec_dh(self.ec_sec_key, self.ec_pub_key)
            ecdh_secret = tls_crypto.point_to_secret(
                ecdh_secret_point, self.neg_group)

        early_secret = tls_crypto.tls_extract_secret(self.csuite, self.psk, None)
        derived_early_secret = tls_crypto.tls_derive_secret(
            self.csuite, early_secret, "derived".encode(), "".encode())
        if self.accept_early_data:
            self.client_early_traffic_secret = \
                tls_crypto.tls_derive_secret(self.csuite, early_secret, "c e traffic".encode(), self.transcript)
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

        self.transcript += shelo_msg
        return shelo_msg

    def tls_13_process_server_hello(self, shelo_msg: bytes):
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
        PSK_mode = False
        DHE_mode = False

        # Parse extensions
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
                pub_key_bytes = ext_bytes[5:]
                ec_pub_key = tls_crypto.convert_x_y_bytes_ec_pub(pub_key_bytes, name_group)
                self.ec_pub_key = ec_pub_key
                DHE_mode = True
            if ext_type == tls_constants.PSK_TYPE:
                selected_identity = int.from_bytes(ext_bytes, byteorder='big')
                PSK = self.psks[selected_identity]["PSK"]
                PSK_mode = True

            curr_ext_pos += ext_len

        # Set PSK and ECDH secrets
        if DHE_mode:
            ec_sec_key = self.ec_sec_keys[name_group]
            shared_secret = tls_crypto.ec_dh(ec_sec_key, ec_pub_key)
            ecdh_secret = tls_crypto.point_to_secret(shared_secret, name_group)
        else:
            ecdh_secret = None

        if PSK_mode:
            early_sec_input_key = PSK
        else:
            early_sec_input_key = None

        # Derive and set secrets based on communication mode
        early_secret = tls_crypto.tls_extract_secret(self.csuite, early_sec_input_key, None)
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

        self.transcript += shelo_msg