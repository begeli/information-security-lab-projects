from io import open
import unittest
import filecmp
import tls_constants
from tls_crypto import *

# The code below is for unit testing the various functions you are going to implement
# There are fourteen modular tests for each
# You can use the public input and output files provided to you for testing the modules you have implemented

TRANSCRIPT_SAMPLES = 100
HKDF_LBL_SAMPLES = 100
DERIVE_KEY_IV_SAMPLES = 90
EXTRACT_SECRET_SAMPLES = 100
DERIVE_SECRET_SAMPLES = 100
FINISHED_KEY_SAMPLES = 30
FINISHED_MAC_SAMPLES = 100
FINISHED_VFY_SAMPLES = 50
AEAD_ENC_SAMPLES = 30
AEAD_DEC_SAMPLES = 60
TLS_NONCE_SAMPLES = 100
SIG_CONTEXT_SAMPLES = 90
SIG_SAMPLES = 45
SIG_VFY_SAMPLES = 45


class Tests(unittest.TestCase):

    # Unit testing for tls_transcript_hash
    def test_tls_transcript_hash(self):
        transcript_mult_out = []
        with open('ut_tls_transcript_hash_int_inputs.txt', 'r') as filehandle:
            with open('ut_tls_transcript_hash_byte_inputs.txt', 'rb') as filehandletwo:
                curr_pos = 0
                context_bytes = filehandletwo.read()
                for i in range(TRANSCRIPT_SAMPLES):
                    line_space = filehandle.readline()
                    transcript_inp = filehandle.readline().split()
                    csuite = int(transcript_inp[0])
                    len_context = int(transcript_inp[1])
                    tmp_pos = curr_pos + len_context
                    context = context_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    transcript_hash = tls_transcript_hash(csuite, context)
                    transcript_mult_out.append(transcript_hash.hex())

        with open('ut_tls_transcript_hash_outputs_temp.txt', 'w', newline='\n') as filehandle:
            for (transcript_hash) in transcript_mult_out:
                filehandle.write('\n%s\n' % (transcript_hash))

        self.assertTrue(filecmp.cmp(
            'ut_tls_transcript_hash_outputs_temp.txt', 'ut_tls_transcript_hash_outputs.txt'))

    # Unit testing for tls_hkdf_lbl
    def test_tls_hkdf_lbl(self):
        hkdf_lbl_mult_out = []
        with open('ut_tls_hkdf_lbl_int_inputs.txt', 'r') as filehandle:
            with open('ut_tls_hkdf_lbl_byte_inputs.txt', 'rb') as filehandletwo:
                curr_pos = 0
                hkdf_lbl_bytes = filehandletwo.read()
                for i in range(HKDF_LBL_SAMPLES):
                    line_space = filehandle.readline()
                    hkdf_len_inp = filehandle.readline().split()
                    length = int(hkdf_len_inp[0])
                    lbl_len = int(hkdf_len_inp[1])
                    ctx_len = int(hkdf_len_inp[2])
                    tmp_pos = curr_pos + lbl_len
                    label_bytes = hkdf_lbl_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    tmp_pos = curr_pos + ctx_len
                    context_bytes = hkdf_lbl_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    hkdf_lbl = tls_hkdf_label(
                        label_bytes, context_bytes, length)
                    hkdf_lbl_mult_out.append(hkdf_lbl.hex())

        with open('ut_tls_hkdf_lbl_outputs_temp.txt', 'w', newline='\n') as filehandle:
            for (hkdf_lbl) in hkdf_lbl_mult_out:
                filehandle.write('\n%s\n' % (hkdf_lbl))

        self.assertTrue(filecmp.cmp(
            'ut_tls_hkdf_lbl_outputs_temp.txt', 'ut_tls_hkdf_lbl_outputs.txt'))

    # Unit testing for tls_derive_key_iv
    def test_tls_derive_key_iv(self):
        derive_key_iv_mult_out = []
        with open('ut_tls_derive_key_iv_int_inputs.txt', 'r') as filehandle:
            with open('ut_tls_derive_key_iv_byte_inputs.txt', 'rb') as filehandletwo:
                curr_pos = 0
                secret_bytes = filehandletwo.read()
                for i in range(DERIVE_KEY_IV_SAMPLES):
                    line_space = filehandle.readline()
                    derive_key_iv_inp = filehandle.readline().split()
                    csuite = int(derive_key_iv_inp[0])
                    len_secret = int(derive_key_iv_inp[1])
                    tmp_pos = curr_pos + len_secret
                    secret = secret_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    key, iv = tls_derive_key_iv(csuite, secret)
                    derive_key_iv_mult_out.append((key.hex(), iv.hex()))

        with open('ut_tls_derive_key_iv_outputs_temp.txt', 'w', newline='\n') as filehandle:
            for ((key, iv)) in derive_key_iv_mult_out:
                filehandle.write('\n%s %s\n' % (key, iv))

        self.assertTrue(filecmp.cmp(
            'ut_tls_derive_key_iv_outputs_temp.txt', 'ut_tls_derive_key_iv_outputs.txt'))

    # Unit testing for tls_extract_secret
    def test_tls_extract_secret(self):
        extract_secret_mult_out = []
        with open('ut_tls_extract_secret_int_inputs.txt', 'r') as filehandle:
            with open('ut_tls_extract_secret_byte_inputs.txt', 'rb') as filehandletwo:
                curr_pos = 0
                extract_secret_bytes = filehandletwo.read()
                for i in range(EXTRACT_SECRET_SAMPLES):
                    line_space = filehandle.readline()
                    extract_secret_inp = filehandle.readline().split()
                    csuite = int(extract_secret_inp[0])
                    mat_len = int(extract_secret_inp[1])
                    slt_len = int(extract_secret_inp[2])
                    tmp_pos = curr_pos + mat_len
                    key_mat_bytes = extract_secret_bytes[curr_pos:tmp_pos]
                    if (mat_len == 0):
                        key_mat_bytes = None
                    curr_pos = tmp_pos
                    tmp_pos = curr_pos + slt_len
                    salt_bytes = extract_secret_bytes[curr_pos:tmp_pos]
                    if (slt_len == 0):
                        salt_bytes = None
                    curr_pos = tmp_pos
                    secret = tls_extract_secret(
                        csuite, key_mat_bytes, salt_bytes)
                    extract_secret_mult_out.append(secret.hex())

        with open('ut_tls_extract_secret_outputs_temp.txt', 'w', newline='\n') as filehandle:
            for (secret) in extract_secret_mult_out:
                filehandle.write('\n%s\n' % (secret))

        self.assertTrue(filecmp.cmp(
            'ut_tls_extract_secret_outputs_temp.txt', 'ut_tls_extract_secret_outputs.txt'))

    # Unit testing for tls_derive_secret
    def test_tls_derive_secret(self):
        derive_secret_mult_out = []
        with open('ut_tls_derive_secret_int_inputs.txt', 'r') as filehandle:
            with open('ut_tls_derive_secret_byte_inputs.txt', 'rb') as filehandletwo:
                curr_pos = 0
                derive_secret_bytes = filehandletwo.read()
                for i in range(DERIVE_SECRET_SAMPLES):
                    line_space = filehandle.readline()
                    derive_secret_inp = filehandle.readline().split()
                    csuite = int(derive_secret_inp[0])
                    sec_len = int(derive_secret_inp[1])
                    lbl_len = int(derive_secret_inp[2])
                    msg_len = int(derive_secret_inp[3])
                    tmp_pos = curr_pos + sec_len
                    secret_bytes = derive_secret_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    tmp_pos = curr_pos + lbl_len
                    label_bytes = derive_secret_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    tmp_pos = curr_pos + msg_len
                    msg_bytes = derive_secret_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    out_secret = tls_derive_secret(
                        csuite, secret_bytes, label_bytes, msg_bytes)
                    derive_secret_mult_out.append(out_secret.hex())

        with open('ut_tls_derive_secret_outputs_temp.txt', 'w', newline='\n') as filehandle:
            for (out_secret) in derive_secret_mult_out:
                filehandle.write('\n%s\n' % (out_secret))

        self.assertTrue(filecmp.cmp(
            'ut_tls_derive_secret_outputs_temp.txt', 'ut_tls_derive_secret_outputs.txt'))

    # Unit testing for tls_finished_key
    def test_tls_finished_key(self):
        finished_key_mult_out = []
        with open('ut_tls_finished_key_int_inputs.txt', 'r') as filehandle:
            with open('ut_tls_finished_key_byte_inputs.txt', 'rb') as filehandletwo:
                curr_pos = 0
                secret_bytes = filehandletwo.read()
                for i in range(FINISHED_KEY_SAMPLES):
                    line_space = filehandle.readline()
                    finished_key_inp = filehandle.readline().split()
                    csuite = int(finished_key_inp[0])
                    len_secret = int(finished_key_inp[1])
                    tmp_pos = curr_pos + len_secret
                    secret = secret_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    finished_key = tls_finished_key_derive(csuite, secret)
                    finished_key_mult_out.append(finished_key.hex())

        with open('ut_tls_finished_key_outputs_temp.txt', 'w', newline='\n') as filehandle:
            for (finished_key) in finished_key_mult_out:
                filehandle.write('\n%s\n' % (finished_key))

        self.assertTrue(filecmp.cmp(
            'ut_tls_finished_key_outputs_temp.txt', 'ut_tls_finished_key_outputs.txt'))

    # Unit testing for tls_finished_mac
    def test_tls_finished_mac(self):
        finished_mac_mult_out = []
        with open('ut_tls_finished_mac_int_inputs.txt', 'r') as filehandle:
            with open('ut_tls_finished_mac_byte_inputs.txt', 'rb') as filehandletwo:
                curr_pos = 0
                finished_mac_bytes = filehandletwo.read()
                for i in range(FINISHED_MAC_SAMPLES):
                    line_space = filehandle.readline()
                    finished_mac_inp = filehandle.readline().split()
                    csuite = int(finished_mac_inp[0])
                    key_len = int(finished_mac_inp[1])
                    ctx_len = int(finished_mac_inp[2])
                    tmp_pos = curr_pos + key_len
                    key_bytes = finished_mac_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    tmp_pos = curr_pos + ctx_len
                    context_bytes = finished_mac_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    tag = tls_finished_mac(csuite, key_bytes, context_bytes)
                    finished_mac_mult_out.append(tag.hex())

        with open('ut_tls_finished_mac_outputs_temp.txt', 'w', newline='\n') as filehandle:
            for (tag) in finished_mac_mult_out:
                filehandle.write('\n%s\n' % (tag))

        self.assertTrue(filecmp.cmp(
            'ut_tls_finished_mac_outputs_temp.txt', 'ut_tls_finished_mac_outputs.txt'))

    # Unit testing for tls_finished_mac_vfy

    def test_tls_finished_mac_vfy(self):
        with open('ut_tls_finished_mac_vfy_int_inputs.txt', 'r') as filehandle:
            with open('ut_tls_finished_mac_vfy_byte_inputs.txt', 'rb') as filehandletwo:
                curr_pos = 0
                finished_mac_vfy_bytes = filehandletwo.read()
                for i in range(FINISHED_VFY_SAMPLES):
                    line_space = filehandle.readline()
                    finished_mac_vfy_inp = filehandle.readline().split()
                    csuite = int(finished_mac_vfy_inp[0])
                    key_len = int(finished_mac_vfy_inp[1])
                    ctx_len = int(finished_mac_vfy_inp[2])
                    tag_len = int(finished_mac_vfy_inp[2])
                    tmp_pos = curr_pos + key_len
                    key_bytes = finished_mac_vfy_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    tmp_pos = curr_pos + ctx_len
                    context_bytes = finished_mac_vfy_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    tmp_pos = curr_pos + tag_len
                    tag_bytes = finished_mac_vfy_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    tag = tls_finished_mac_verify(
                        csuite, key_bytes, context_bytes, tag_bytes)

    # Unit testing for tls_aead_encrypt
    def test_tls_aead_encrypt(self):
        aead_enc_mult_out = []
        with open('ut_tls_aead_encrypt_int_inputs.txt', 'r') as filehandle:
            with open('ut_tls_aead_encrypt_byte_inputs.txt', 'rb') as filehandletwo:
                curr_pos = 0
                aead_encrypt_bytes = filehandletwo.read()
                for i in range(AEAD_ENC_SAMPLES):
                    line_space = filehandle.readline()
                    aead_encrypt_inp = filehandle.readline().split()
                    csuite = int(aead_encrypt_inp[0])
                    key_len = int(aead_encrypt_inp[1])
                    nonce_len = int(aead_encrypt_inp[2])
                    ptxt_len = int(aead_encrypt_inp[3])
                    tmp_pos = curr_pos + key_len
                    key_bytes = aead_encrypt_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    tmp_pos = curr_pos + nonce_len
                    nonce_bytes = aead_encrypt_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    tmp_pos = curr_pos + ptxt_len
                    ptxt_bytes = aead_encrypt_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    ctxt = tls_aead_encrypt(
                        csuite, key_bytes, nonce_bytes, ptxt_bytes)
                    aead_enc_mult_out.append(ctxt.hex())

        with open('ut_tls_aead_encrypt_outputs_temp.txt', 'w', newline='\n') as filehandle:
            for (ctxt) in aead_enc_mult_out:
                filehandle.write('\n%s\n' % (ctxt))

        self.assertTrue(filecmp.cmp(
            'ut_tls_aead_encrypt_outputs_temp.txt', 'ut_tls_aead_encrypt_outputs.txt'))

    # Unit testing for tls_aead_decrypt
    def test_tls_aead_decrypt(self):
        aead_dec_mult_out = []
        with open('ut_tls_aead_decrypt_int_inputs.txt', 'r') as filehandle:
            with open('ut_tls_aead_decrypt_byte_inputs.txt', 'rb') as filehandletwo:
                curr_pos = 0
                aead_decrypt_bytes = filehandletwo.read()
                for i in range(AEAD_DEC_SAMPLES):
                    line_space = filehandle.readline()
                    aead_decrypt_inp = filehandle.readline().split()
                    csuite = int(aead_decrypt_inp[0])
                    key_len = int(aead_decrypt_inp[1])
                    nonce_len = int(aead_decrypt_inp[2])
                    ptxt_len = int(aead_decrypt_inp[3])
                    tmp_pos = curr_pos + key_len
                    key_bytes = aead_decrypt_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    tmp_pos = curr_pos + nonce_len
                    nonce_bytes = aead_decrypt_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    tmp_pos = curr_pos + ptxt_len
                    ctxt_bytes = aead_decrypt_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    ptxt = tls_aead_decrypt(
                        csuite, key_bytes, nonce_bytes, ctxt_bytes)
                    aead_dec_mult_out.append(ptxt.hex())

        with open('ut_tls_aead_decrypt_outputs_temp.txt', 'w', newline='\n') as filehandle:
            for (ptxt) in aead_dec_mult_out:
                filehandle.write('\n%s\n' % (ptxt))

        self.assertTrue(filecmp.cmp(
            'ut_tls_aead_decrypt_outputs_temp.txt', 'ut_tls_aead_decrypt_outputs.txt'))

    # Unit testing for tls_nonce
    def test_tls_nonce(self):
        tls_nonce_mult_out = []
        with open('ut_tls_nonce_int_inputs.txt', 'r') as filehandle:
            with open('ut_tls_nonce_byte_inputs.txt', 'rb') as filehandletwo:
                curr_pos = 0
                nonce_bytes = filehandletwo.read()
                for i in range(TLS_NONCE_SAMPLES):
                    line_space = filehandle.readline()
                    tls_nonce_inp = filehandle.readline().split()
                    csuite = int(tls_nonce_inp[0])
                    sqn_no = int(tls_nonce_inp[1])
                    iv_len = int(tls_nonce_inp[2])
                    tmp_pos = curr_pos + iv_len
                    iv_bytes = nonce_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    nonce = tls_nonce(csuite, sqn_no, iv_bytes)
                    tls_nonce_mult_out.append(nonce.hex())

        with open('ut_tls_nonce_outputs_temp.txt', 'w', newline='\n') as filehandle:
            for (nonce) in tls_nonce_mult_out:
                filehandle.write('\n%s\n' % (nonce))

        self.assertTrue(filecmp.cmp(
            'ut_tls_nonce_outputs_temp.txt', 'ut_tls_nonce_outputs.txt'))

    # Unit testing for tls_sig_context

    def test_tls_sig_context(self):
        sig_context_mult_out = []
        with open('ut_tls_sig_context_int_inputs.txt', 'r') as filehandle:
            with open('ut_tls_sig_context_byte_inputs.txt', 'rb') as filehandletwo:
                curr_pos = 0
                sig_context_bytes = filehandletwo.read()
                for i in range(SIG_CONTEXT_SAMPLES):
                    line_space = filehandle.readline()
                    sig_context_inp = filehandle.readline().split()
                    context_flag = sig_context_inp[0]
                    ctx_len = int(sig_context_inp[1])
                    tmp_pos = curr_pos + ctx_len
                    ctx_bytes = sig_context_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    message = tls_signature_context(context_flag, ctx_bytes)
                    sig_context_mult_out.append(message.hex())

        with open('ut_tls_sig_context_outputs_temp.txt', 'w', newline='\n') as filehandle:
            for (message) in sig_context_mult_out:
                filehandle.write('\n%s\n' % (message))

        self.assertTrue(filecmp.cmp(
            'ut_tls_sig_context_outputs_temp.txt', 'ut_tls_sig_context_outputs.txt'))

    # Unit testing for tls_signature
    def test_tls_signature(self):
        sig_mult_out = []
        with open('ut_tls_signature_int_inputs.txt', 'r') as filehandle:
            with open('ut_tls_signature_byte_inputs.txt', 'rb') as filehandletwo:
                curr_pos = 0
                sig_bytes = filehandletwo.read()
                for i in range(SIG_SAMPLES):
                    line_space = filehandle.readline()
                    sig_inp = filehandle.readline().split()
                    sig_alg = int(sig_inp[0])
                    msg_len = int(sig_inp[1])
                    context_flag = sig_inp[2]
                    tmp_pos = curr_pos + msg_len
                    msg_bytes = sig_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    signature = tls_signature(sig_alg, msg_bytes, context_flag)

                    if (sig_alg == tls_constants.RSA_PKCS1_SHA256):
                        server_cert = tls_constants.RSA2048_SHA256_CERT
                        server_public_key = get_rsa_pk_from_cert(server_cert)
                    if (sig_alg == tls_constants.RSA_PKCS1_SHA384):
                        server_cert = tls_constants.RSA2048_SHA384_CERT
                        server_public_key = get_rsa_pk_from_cert(server_cert)
                    if (sig_alg == tls_constants.ECDSA_SECP384R1_SHA384):
                        server_cert = tls_constants.SECP384R1_SHA384_CERT
                        server_public_key = get_ecdsa_pk_from_cert(server_cert)
                    result = tls_verify_signature(
                        sig_alg, msg_bytes, context_flag, signature, server_public_key)

    # Unit testing for tls_verify_signature

    def test_tls_verify_signature(self):
        with open('ut_tls_signature_vfy_int_inputs.txt', 'r') as filehandle:
            with open('ut_tls_signature_vfy_byte_inputs.txt', 'rb') as filehandletwo:
                curr_pos = 0
                sig_vfy_bytes = filehandletwo.read()
                for i in range(SIG_VFY_SAMPLES):
                    line_space = filehandle.readline()
                    sig_vfy_inp = filehandle.readline().split()
                    sig_alg = int(sig_vfy_inp[0])
                    msg_len = int(sig_vfy_inp[1])
                    context_flag = sig_vfy_inp[2]
                    sig_len = int(sig_vfy_inp[3])
                    tmp_pos = curr_pos + msg_len
                    msg_bytes = sig_vfy_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    tmp_pos = curr_pos + sig_len
                    sig_bytes = sig_vfy_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    if (sig_alg == tls_constants.RSA_PKCS1_SHA256):
                        server_cert = tls_constants.RSA2048_SHA256_CERT
                        server_public_key = get_rsa_pk_from_cert(server_cert)
                    if (sig_alg == tls_constants.RSA_PKCS1_SHA384):
                        server_cert = tls_constants.RSA2048_SHA384_CERT
                        server_public_key = get_rsa_pk_from_cert(server_cert)
                    if (sig_alg == tls_constants.ECDSA_SECP384R1_SHA384):
                        server_cert = tls_constants.SECP384R1_SHA384_CERT
                        server_public_key = get_ecdsa_pk_from_cert(server_cert)
                    result = tls_verify_signature(
                        sig_alg, msg_bytes, context_flag, sig_bytes, server_public_key)
