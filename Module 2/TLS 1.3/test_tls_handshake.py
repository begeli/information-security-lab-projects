from io import open
import unittest
import filecmp
import tls_constants
import tls_crypto
from tls_handshake import *

# The code below is for unit testing the various functions you are going to implement
# There are four modular tests for each
# You can use the public input and output files provided to you for testing the modules you have implemented

CHELO_SAMPLES = 20
FINISHED_SAMPLES = 15
SIG_VFY_SAMPLES = 30
SHELO_SAMPLES = 10


class Tests(unittest.TestCase):

    # Unit testing for tls_13_client_hello()
    def test_chelo_msg(self):
        chelo_mult_out = []
        with open('ut_tls_chelo_int_inputs.txt', 'r') as filehandle:
            for i in range(CHELO_SAMPLES):
                line_space = filehandle.readline()
                chelo_inp = filehandle.readline().split()
                j = 0
                role = chelo_inp[j]
                j = j + 1
                num_csuites = int(chelo_inp[j])
                j = j + 1
                csuites = []
                for k in range(num_csuites):
                    csuites.append(int(chelo_inp[j+k]))
                j = j + num_csuites
                num_vers = int(chelo_inp[j])
                j = j + 1
                vers = []
                for k in range(num_vers):
                    vers.append(int(chelo_inp[j+k]))
                j = j + num_vers
                num_groups = int(chelo_inp[j])
                j = j + 1
                groups = []
                for k in range(num_groups):
                    groups.append(int(chelo_inp[j+k]))
                j = j + num_groups
                num_sigs = int(chelo_inp[j])
                j = j + 1
                sigs = []
                for k in range(num_sigs):
                    sigs.append(int(chelo_inp[j+k]))
                j = j + num_sigs
                client_extensions = {
                    tls_constants.SUPPORT_VERS_TYPE: vers,
                    tls_constants.SUPPORT_GROUPS_TYPE: groups,
                    tls_constants.SIG_ALGS_TYPE: sigs
                }
                test_client = Handshake(csuites, client_extensions, role)
                chelo_output = test_client.tls_13_client_hello()
                curr_pos = 0
                curr_msg_type = chelo_output[curr_pos]
                curr_pos = curr_pos + tls_constants.MSG_TYPE_LEN
                msg_len = int.from_bytes(
                    chelo_output[curr_pos:curr_pos + tls_constants.MSG_LEN_LEN], 'big')
                curr_pos = curr_pos + tls_constants.MSG_LEN_LEN
                chelo_vers = chelo_output[curr_pos:curr_pos +
                                          tls_constants.MSG_VERS_LEN]
                curr_pos = curr_pos + tls_constants.MSG_VERS_LEN
                curr_pos = curr_pos + tls_constants.RANDOM_LEN
                chelo_sess_id_len = chelo_output[curr_pos]
                curr_pos = curr_pos + tls_constants.SID_LEN_LEN
                curr_pos = curr_pos+chelo_sess_id_len
                csuites_len = int.from_bytes(
                    chelo_output[curr_pos:curr_pos+tls_constants.CSUITE_LEN_LEN], 'big')
                curr_pos = curr_pos + tls_constants.CSUITE_LEN_LEN
                remote_csuites = chelo_output[curr_pos:curr_pos+csuites_len]
                curr_pos = curr_pos + csuites_len
                comp_len = int.from_bytes(
                    chelo_output[curr_pos:curr_pos+tls_constants.COMP_LEN_LEN], 'big')
                curr_pos = curr_pos + tls_constants.COMP_LEN_LEN
                legacy_comp = chelo_output[curr_pos]
                curr_pos = curr_pos + comp_len
                exts_len = int.from_bytes(
                    chelo_output[curr_pos:curr_pos+tls_constants.EXT_LEN_LEN], 'big')
                curr_pos = curr_pos + tls_constants.EXT_LEN_LEN
                remote_extensions = chelo_output[curr_pos:]

                curr_ext_pos = 0
                while (curr_ext_pos < len(remote_extensions)):
                    ext_type = int.from_bytes(
                        remote_extensions[curr_ext_pos:curr_ext_pos+2], 'big')
                    ext_bytes = remote_extensions[curr_ext_pos:curr_ext_pos+2]
                    curr_ext_pos = curr_ext_pos + 2
                    ext_len = int.from_bytes(
                        remote_extensions[curr_ext_pos:curr_ext_pos+2], 'big')
                    ext_bytes = ext_bytes + \
                        remote_extensions[curr_ext_pos:curr_ext_pos+2]
                    curr_ext_pos = curr_ext_pos + 2
                    ext_bytes = ext_bytes + \
                        remote_extensions[curr_ext_pos:curr_ext_pos+ext_len]
                    if (ext_type == tls_constants.SUPPORT_VERS_TYPE):
                        deter_vers = ext_bytes
                    if (ext_type == tls_constants.SUPPORT_GROUPS_TYPE):
                        deter_group = ext_bytes
                    if (ext_type == tls_constants.KEY_SHARE_TYPE):
                        deter_keys = ext_bytes
                    if (ext_type == tls_constants.SIG_ALGS_TYPE):
                        deter_sig = ext_bytes
                    curr_ext_pos = curr_ext_pos + ext_len
                deter_chelo = curr_msg_type.to_bytes(1, 'big') + chelo_vers + csuites_len.to_bytes(
                    2, 'big') + remote_csuites + comp_len.to_bytes(1, 'big') + legacy_comp.to_bytes(1, 'big')
                server = Handshake(tls_constants.SERVER_SUPPORTED_CIPHERSUITES,
                                   tls_constants.SERVER_SUPPORTED_EXTENSIONS, tls_constants.SERVER_FLAG)
                result = ""
                try:
                    server.tls_13_process_client_hello(chelo_output)
                    result = result + "successfully parsed"
                except:
                    result = result + "failed to parse"
                chelo_mult_out.append(deter_chelo.hex(
                ) + deter_vers.hex() + deter_group.hex() + deter_sig.hex() + " " + result)

        with open('ut_tls_chelo_outputs_temp.txt', 'w', newline='\n') as filehandle:
            for determ_chelo in chelo_mult_out:
                filehandle.write('\n%s\n' % (determ_chelo))

        self.assertTrue(filecmp.cmp(
            'ut_tls_chelo_outputs_temp.txt', 'ut_tls_chelo_outputs.txt'))

    # Unit testing for tls_13_process_finished() function
    def test_process_finished(self):
        finish_mult_out = []
        with open('ut_tls_process_finished_int_inputs.txt', 'r') as filehandle:
            with open('ut_tls_process_finished_byte_inputs.txt', 'rb') as filehandletwo:
                curr_pos = 0
                finished_bytes = filehandletwo.read()
                for i in range(FINISHED_SAMPLES):
                    line_space = filehandle.readline()
                    finished_inp = filehandle.readline().split()
                    csuite = int(finished_inp[0])
                    len_fin = int(finished_inp[1])
                    len_transcript = int(finished_inp[2])
                    len_hs_secret = int(finished_inp[3])
                    len_ms_secret = int(finished_inp[4])
                    tmp_pos = curr_pos + len_fin
                    fin_msg = finished_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    tmp_pos = curr_pos + len_transcript
                    transcript = finished_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    tmp_pos = curr_pos + len_hs_secret
                    hs_secret = finished_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    tmp_pos = curr_pos + len_ms_secret
                    ms_secret = finished_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    client = Handshake(tls_constants.CLIENT_SUPPORTED_CIPHERSUITES,
                                       tls_constants.CLIENT_SUPPORTED_EXTENSIONS, tls_constants.CLIENT_FLAG)
                    client.csuite = csuite
                    client.transcript = transcript
                    client.server_hs_traffic_secret = hs_secret
                    client.master_secret = ms_secret
                    client.tls_13_process_finished(fin_msg)
                    out_transcript = client.transcript
                    finish_mult_out.append(out_transcript.hex())

        with open('ut_tls_process_finished_outputs_temp.txt', 'w', newline='\n') as filehandle:
            for (out_transcript) in finish_mult_out:
                filehandle.write('\n%s\n' % (out_transcript))

        self.assertTrue(filecmp.cmp(
            'ut_tls_process_finished_outputs_temp.txt', 'ut_tls_process_finished_outputs.txt'))

    # Unit testing for tls_13_process_server_cert_verify()
    def test_process_server_cert_verify(self):
        scert_verify_mult_out = []
        with open('ut_tls_process_server_cert_verify_int_inputs.txt', 'r') as filehandle:
            with open('ut_tls_process_server_cert_verify_byte_inputs.txt', 'rb') as filehandletwo:
                curr_pos = 0
                cert_verify_bytes = filehandletwo.read()
                for i in range(SIG_VFY_SAMPLES):
                    line_space = filehandle.readline()
                    cert_verify_inp = filehandle.readline().split()
                    csuite = int(cert_verify_inp[0])
                    len_server_cert_string = int(cert_verify_inp[1])
                    len_transcript = int(cert_verify_inp[2])
                    len_vfy_msg = int(cert_verify_inp[3])
                    tmp_pos = curr_pos + len_server_cert_string
                    server_cert_string = cert_verify_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    tmp_pos = curr_pos + len_transcript
                    transcript = cert_verify_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    tmp_pos = curr_pos + len_vfy_msg
                    vfy_msg = cert_verify_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    client = Handshake(tls_constants.CLIENT_SUPPORTED_CIPHERSUITES,
                                       tls_constants.CLIENT_SUPPORTED_EXTENSIONS, tls_constants.CLIENT_FLAG)
                    client.csuite = csuite
                    client.transcript = transcript
                    client.server_cert_string = server_cert_string.decode()
                    client.tls_13_process_server_cert_verify(vfy_msg)
                    out_transcript = client.transcript
                    scert_verify_mult_out.append(out_transcript.hex())

        with open('ut_tls_process_server_cert_verify_outputs_temp.txt', 'w', newline='\n') as filehandle:
            for (out_transcript) in scert_verify_mult_out:
                filehandle.write('\n%s\n' % (out_transcript))

        self.assertTrue(filecmp.cmp(
            'ut_tls_process_server_cert_verify_outputs_temp.txt', 'ut_tls_process_server_cert_verify_outputs.txt'))

    # Unit testing for tls_13_process_server_hello()
    def test_process_server_hello(self):
        server_hello_mult_out = []
        with open('ut_tls_process_server_hello_int_inputs.txt', 'r') as filehandle:
            with open('ut_tls_process_server_hello_byte_inputs.txt', 'rb') as filehandletwo:
                curr_pos = 0
                server_hello_bytes = filehandletwo.read()
                for i in range(SHELO_SAMPLES):
                    line_space = filehandle.readline()
                    shelo_inp = filehandle.readline().split()
                    len_transcript = int(shelo_inp[0])
                    secp256r1_sec_key = int(shelo_inp[1])
                    secp384r1_sec_key = int(shelo_inp[2])
                    secp521r1_sec_key = int(shelo_inp[3])
                    len_shelo = int(shelo_inp[4])
                    tmp_pos = curr_pos + len_transcript
                    first_transcript = server_hello_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    tmp_pos = curr_pos + len_shelo
                    shelo_msg = server_hello_bytes[curr_pos:tmp_pos]
                    curr_pos = tmp_pos
                    client = Handshake(tls_constants.CLIENT_SUPPORTED_CIPHERSUITES,
                                       tls_constants.CLIENT_SUPPORTED_EXTENSIONS, tls_constants.CLIENT_FLAG)
                    client.transcript = first_transcript
                    client.ec_sec_keys[tls_constants.SECP256R1_VALUE] = secp256r1_sec_key
                    client.ec_sec_keys[tls_constants.SECP384R1_VALUE] = secp384r1_sec_key
                    client.ec_sec_keys[tls_constants.SECP521R1_VALUE] = secp521r1_sec_key
                    client.tls_13_process_server_hello(shelo_msg)
                    out_transcript = client.transcript
                    out_csuite = client.csuite.to_bytes(2, 'big')
                    out_group = client.neg_group.to_bytes(2, 'big')
                    out_vers = client.neg_version.to_bytes(2, 'big')
                    out_ec_pub_key = tls_crypto.convert_ec_pub_bytes(
                        client.ec_pub_key, client.neg_group)
                    out_local_hs_traffic_secret = client.client_hs_traffic_secret
                    out_remote_hs_traffic_secret = client.server_hs_traffic_secret
                    out_master_secret = client.master_secret
                    server_hello_mult_out.append(out_transcript.hex() + out_csuite.hex() + out_vers.hex() + out_group.hex(
                    ) + out_ec_pub_key.hex() + out_local_hs_traffic_secret.hex() + out_remote_hs_traffic_secret.hex() + out_master_secret.hex())

        with open('ut_tls_process_server_hello_outputs_temp.txt', 'w', newline='\n') as filehandle:
            for output in server_hello_mult_out:
                filehandle.write('\n%s\n' % (output))

        self.assertTrue(filecmp.cmp(
            'ut_tls_process_server_hello_outputs_temp.txt', 'ut_tls_process_server_hello_outputs.txt'))


if __name__ == '__main__':
    unittest.main()
