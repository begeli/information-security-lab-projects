#!/usr/bin/env python

'''
tls_record_layer.py:
Implementation of the TLS 1.3 Record Layer Protocol
'''

from typing import Tuple
from tls_crypto import tls_aead_encrypt, tls_aead_decrypt, tls_nonce
import tls_constants
from tls_error import WrongLengthError, WrongVersionError


def add_padding(ptxt, csuite):
    if csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256:
        pad_ptxt = ptxt
    else:
        pad_len = tls_constants.AES_BLOCK_LEN - (len(ptxt) % 16)
        if pad_len == 0:
            pad_len = tls_constants.AES_BLOCK_LEN
        pad = b'\0' * (pad_len - 1)
        last_byte = pad_len.to_bytes(1, 'big')
        pad = pad + last_byte
        pad_ptxt = ptxt + pad
    return pad_ptxt


def create_TLSPlaintext(ptxt: bytes, content_type: int) -> bytes:
    ptxt_len = len(ptxt)
    type_bytes = content_type.to_bytes(1, 'big')
    legacy_bytes = tls_constants.LEGACY_VERSION.to_bytes(2, 'big')
    len_bytes = ptxt_len.to_bytes(2, 'big')
    tls_ptxt = type_bytes + legacy_bytes + len_bytes + ptxt
    return tls_ptxt


def create_ccs_packet() -> bytes:
    type_bytes = tls_constants.CHANGE_TYPE.to_bytes(1, 'big')
    legacy_bytes = tls_constants.LEGACY_VERSION.to_bytes(2, 'big')
    ptxt_len = 1
    len_bytes = ptxt_len.to_bytes(2, 'big')
    payload_bytes = ptxt_len.to_bytes(1, 'big')
    ccs_ptxt = type_bytes + legacy_bytes + len_bytes + payload_bytes
    return ccs_ptxt


def read_TLSPlaintext(ptxt: bytes) -> Tuple[int, bytes]:
    msg_type = ptxt[0]
    version = ptxt[1:3]
    ptxt_len = ptxt[3:5]
    ptxt_bytes = ptxt[5:]
    p_len = int.from_bytes(ptxt_len, 'big')
    if p_len != len(ptxt_bytes):
        raise WrongLengthError()
    if version != tls_constants.LEGACY_VERSION.to_bytes(2, 'big'):
        raise WrongVersionError()
    return msg_type, ptxt_bytes


class ProtectedRecordLayer:
    def __init__(self, key, iv, csuite, role):
        self.role = role
        if self.role == tls_constants.RECORD_WRITE:
            self.write_key = key
            self.write_iv = iv
        if self.role == tls_constants.RECORD_READ:
            self.read_key = key
            self.read_iv = iv
        self.ciphersuite = csuite
        self.sqn_no = 0

    def create_TLSInnerPlaintext(self, ptxt: bytes, content_type, padding: bytes) -> bytes:
        return ptxt + content_type.to_bytes(1, 'big') + padding

    def enc_packet(self, ptxt: bytes, content_type=tls_constants.APPLICATION_TYPE) -> bytes:
        inner_ptxt = self.create_TLSInnerPlaintext(
            ptxt, content_type, ''.encode())
        legacy_type_bytes = tls_constants.APPLICATION_TYPE.to_bytes(1, 'big')
        legacy_vers_bytes = tls_constants.LEGACY_VERSION.to_bytes(2, 'big')
        nonce = tls_nonce(self.ciphersuite, self.sqn_no, self.write_iv)
        ctxt = tls_aead_encrypt(
            self.ciphersuite, self.write_key, nonce, inner_ptxt)
        len_ctxt = len(ctxt)
        len_bytes = len_ctxt.to_bytes(2, 'big')
        header = legacy_type_bytes + legacy_vers_bytes + len_bytes
        tls_record = header + ctxt
        self.sqn_no = self.sqn_no + 1
        return tls_record

    def dec_packet(self, tls_record: bytes) -> Tuple[int, bytes]:
        nonce = tls_nonce(self.ciphersuite, self.sqn_no, self.read_iv)
        header = tls_record[:5]
        len_ctxt = int.from_bytes(header[3:5], 'big')
        ciphertext = tls_record[5:5+len_ctxt]
        plaintext = tls_aead_decrypt(
            self.ciphersuite, self.read_key, nonce, ciphertext)
        self.sqn_no = self.sqn_no + 1
        # remove padding
        type_idx = -1
        while plaintext[type_idx] == 0 and type_idx >= -len(plaintext):
            type_idx -= 1
        return plaintext[type_idx], plaintext[:type_idx]
