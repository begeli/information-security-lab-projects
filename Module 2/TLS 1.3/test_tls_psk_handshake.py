import unittest
import pickle
from io import open
from Cryptodome.Random import get_random_bytes
from tls_psk_handshake import PSKHandshake, timer
from tls_error import TLSError


SAMPLES = 15


class Tests(unittest.TestCase):

    def test_tls_13_server_new_session_ticket(self):
        self.maxDiff = None
        with open('ut_tls_13_server_new_session_ticket.txt', 'r', newline='\n') as input:
            with open('ut_tls_13_server_new_session_ticket_out.txt', 'r', newline='\n') as output:
                for _ in range(SAMPLES):
                    handshake = pickle.loads(bytes.fromhex(input.readline()))
                    handshake.get_random_bytes=get_random_bytes
                    handshake.get_time=timer
                    nst_msg_ref = bytes.fromhex(output.readline())
                    handshake.get_random_bytes = lambda n: handshake.rand_id.to_bytes(
                        n, 'big')
                    nst_msg = handshake.tls_13_server_new_session_ticket()

                    self.assertEqual(nst_msg, nst_msg_ref)

    def test_tls_13_client_parse_new_session_ticket(self):
        neg_samples = 10
        self.maxDiff = None
        with open('ut_tls_13_client_parse_new_session_ticket.txt', 'r', newline='\n') as input:
            with open('ut_tls_13_client_parse_new_session_ticket_out.txt', 'r', newline='\n') as output:
                for _ in range(SAMPLES*2):
                    handshake = pickle.loads(bytes.fromhex(input.readline()))
                    handshake.get_random_bytes=get_random_bytes
                    handshake.get_time=timer
                    nst_msg = bytes.fromhex(input.readline())
                    arrival = int(input.readline())
                    psk_dict_ref = pickle.loads(
                        bytes.fromhex(output.readline()))
                    handshake.get_time = lambda: arrival
                    res = handshake.tls_13_client_parse_new_session_ticket(
                        nst_msg)
                    handshake.get_time = timer

                    self.assertDictEqual(psk_dict_ref, res)

                for _ in range(neg_samples):
                    handshake = pickle.loads(bytes.fromhex(input.readline()))
                    handshake.get_random_bytes=get_random_bytes
                    handshake.get_time=timer
                    nst_msg = bytes.fromhex(input.readline())
                    arrival = int(input.readline())
                    with self.assertRaises(TLSError):
                        res = handshake.tls_13_client_parse_new_session_ticket(
                            nst_msg)

    def test_tls_13_client_prep_psk_mode_extension(self):
        self.maxDiff = None
        with open('ut_tls_13_client_prep_psk_mode_extension.txt', 'r', newline='\n') as input:
            with open('ut_tls_13_client_prep_psk_mode_extension_out.txt', 'r', newline='\n') as output:
                for _ in range(SAMPLES):
                    handshake = pickle.loads(bytes.fromhex(input.readline()))
                    handshake.get_random_bytes=get_random_bytes
                    handshake.get_time=timer
                    psk_mode_ext = bytes.fromhex(output.readline())
                    res = handshake.tls_13_client_prep_psk_mode_extension()
                    self.assertEqual(psk_mode_ext, res)

    def test_tls_13_client_add_psk_extension(self):
        self.maxDiff = None
        with open('ut_tls_13_client_add_psk_extension.txt', 'r', newline='\n') as input:
            with open('ut_tls_13_client_add_psk_extension_out.txt', 'r', newline='\n') as output:
                for _ in range(SAMPLES):
                    handshake = pickle.loads(bytes.fromhex(input.readline()))
                    handshake.get_random_bytes=get_random_bytes
                    handshake.get_time=timer
                    chelo = bytes.fromhex(input.readline())
                    ext = bytes.fromhex(input.readline())
                    now = int(input.readline())
                    handshake.get_time = lambda: now
                    psk_ext_ref = bytes.fromhex(output.readline())
                    psks_offered_ref = pickle.loads(
                        bytes.fromhex(output.readline()))
                    psk_ext, psks_offered = handshake.tls_13_client_add_psk_extension(
                        chelo, ext)
                    self.assertListEqual(psks_offered_ref, psks_offered)
                    self.assertEqual(psk_ext_ref, psk_ext)

        with open('ut_tls_13_client_add_psk_extension.txt', 'r', newline='\n') as input:
            with open('ut_tls_13_client_add_psk_extension_out.txt', 'r', newline='\n') as output:
                for _ in range(SAMPLES):
                    handshake = pickle.loads(bytes.fromhex(input.readline()))
                    handshake.get_random_bytes=get_random_bytes
                    handshake.get_time=timer
                    chelo = bytes.fromhex(input.readline())
                    ext = bytes.fromhex(input.readline())
                    now = int(input.readline())
                    handshake.get_time = lambda: now + 604800*1000
                    psk_ext_ref = bytes.fromhex(output.readline())
                    psks_offered_ref = pickle.loads(
                        bytes.fromhex(output.readline()))
                    psk_ext, psks_offered = handshake.tls_13_client_add_psk_extension(
                        chelo, ext)
                    self.assertNotEqual(psks_offered_ref, psks_offered)
                    self.assertNotEqual(psk_ext_ref, psk_ext)

    def test_tls_13_server_parse_psk_extension(self):
        self.maxDiff = None
        neg_samples = 2
        with open('ut_tls_13_server_parse_psk_extension.txt', 'r', newline='\n') as input:
            with open('ut_tls_13_server_parse_psk_extension_out.txt', 'r', newline='\n') as output:
                for _ in range(SAMPLES):
                    handshake = pickle.loads(bytes.fromhex(input.readline()))
                    handshake.get_random_bytes=get_random_bytes
                    handshake.get_time=timer
                    psk_ext = bytes.fromhex(input.readline())
                    psk_ref = bytes.fromhex(output.readline())
                    identity_ref = int(output.readline())
                    psk, identity = handshake.tls_13_server_parse_psk_extension(
                        psk_ext)
                    self.assertEqual(psk_ref, psk)
                    self.assertEqual(identity_ref, identity)

                for _ in range(neg_samples):
                    handshake = pickle.loads(bytes.fromhex(input.readline()))
                    handshake.get_random_bytes=get_random_bytes
                    handshake.get_time=timer
                    psk_ext = bytes.fromhex(input.readline())
                    with self.assertRaises(TLSError):
                        psk, identity = handshake.tls_13_server_parse_psk_extension(
                            psk_ext)
