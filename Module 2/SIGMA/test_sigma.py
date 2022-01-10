#!/usr/bin/env python3
import unittest
import os
import pickle
from Cryptodome.PublicKey import ECC
from tinyec import registry
from random import Random
from sigma import (
    PRNG,
    SigError,
    MacError,
    SIGMA,
    parse_client_hello,
    parse_ecdsa_client_resp,
    parse_ecdsa_server_hello_id_hide,
    parse_ecdsa_ptxt,
    parse_ecdsa_server_hello,
)

TEST_DATA_SESSIONS_PATH = os.path.join(
    os.path.dirname(__file__), "sigma_session.pkl"
)
TEST_DATA_SESSIONS_PRIVATE_PATH = os.path.join(
    os.path.dirname(__file__), "sigma_session_private.pkl"
)
ROLE_CLIENT = 0
ROLE_SERVER = 1

OFFSET_KEYGEN = 0
OFFSET_ROUND1 = 1
OFFSET_ROUND2 = 2

TEST_ECDH_CURVE = "secp256r1"
TEST_ECDSA_CURVE = "P-256"
TEST_EC_COORDINATE_LEN = 32


def ec_setup_test(curve_name):
    curve = registry.get_curve(curve_name)
    return curve


def convert_ec_pub_bytes_test(ec_pub_key):
    x_int = ec_pub_key.x
    y_int = ec_pub_key.y
    x_bytes = x_int.to_bytes(TEST_EC_COORDINATE_LEN, byteorder="big")
    y_bytes = y_int.to_bytes(TEST_EC_COORDINATE_LEN, byteorder="big")
    return x_bytes, y_bytes


class TestPRNG(PRNG):
    def __init__(self, seed):
        self.rand = Random()
        self.rand.seed(seed)

    def randbelow(self, number: int) -> int:
        return self.rand.randrange(number)

    def get_random_bytes(self, nbytes: int) -> bytes:
        return bytes(self.rand.getrandbits(8) for _ in range(nbytes))
        # return self.rand.randbytes(nbytes) only works for python 3.9

    def reset_seed(self, nseed):
        self.rand.seed(nseed)


def create_test_sigma_with_session_init(
    session, role=ROLE_CLIENT, offset=OFFSET_KEYGEN
):
    return SIGMA(
        TEST_ECDSA_CURVE,
        TEST_ECDH_CURVE,
        session["id"][role],
        session["id_hide_flag"],
        prng=TestPRNG(session["seeds"][role] + offset),
    )


def create_test_sigma_with_session_data(
    session, role=ROLE_CLIENT, offset=OFFSET_KEYGEN
):
    sigma = create_test_sigma_with_session_init(session, role=role, offset=offset)
    sigma.ecdsa_sec_key = ECC.import_key(session["ecdsa_sec_key"][role])
    sigma.register_long_term_keys(
        session["id"][ROLE_CLIENT], session["ecdsa_pub_key"][ROLE_CLIENT]
    )
    sigma.register_long_term_keys(
        session["id"][ROLE_SERVER], session["ecdsa_pub_key"][ROLE_SERVER]
    )
    return sigma


class TestsTask1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(TEST_DATA_SESSIONS_PATH, "rb") as session_file:
            cls.sessions_public = pickle.load(session_file)

    def test_sigma_init(self):
        session = self.sessions_public[0]
        sigma = SIGMA(
            TEST_ECDSA_CURVE, TEST_ECDH_CURVE, session["id"][ROLE_CLIENT], False
        )
        self.assertEqual(sigma.id, session["id"][ROLE_CLIENT])
        self.assertEqual(sigma.ecdsa_curve, TEST_ECDSA_CURVE)
        self.assertEqual(sigma.ecdh_curve, ec_setup_test(TEST_ECDH_CURVE))
        self.assertEqual(sigma.pub_key_dict, {})
        self.assertEqual(sigma.id_hide_flag, False)
        self.assertTrue(isinstance(sigma.prng, PRNG))

    def test_sigma_register_long_term_keys(self):
        for session in self.sessions_public:
            sigma = create_test_sigma_with_session_data(session, role=ROLE_CLIENT)
            self.assertEqual(
                sigma.get_long_term_key(session["id"][ROLE_SERVER]),
                session["ecdsa_pub_key"][ROLE_SERVER],
            )

    def test_key_gen(self):
        for session in self.sessions_public:
            sigma = create_test_sigma_with_session_data(session, role=ROLE_CLIENT)
            out_pub_key = sigma.key_gen()
            self.assertEqual(out_pub_key, session["ecdsa_pub_key"][ROLE_CLIENT])
            self.assertEqual(
                sigma.ecdsa_sec_key.export_key(format="PEM"),
                session["ecdsa_sec_key"][ROLE_CLIENT],
            )


class TestsTask2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(TEST_DATA_SESSIONS_PATH, "rb") as session_file:
            cls.sessions_public = pickle.load(session_file)

    def test_client_init_data(self):
        for session in self.sessions_public:
            sigma = create_test_sigma_with_session_data(
                session, role=ROLE_CLIENT, offset=OFFSET_ROUND1
            )
            out_msg = sigma.client_init()
            self.assertEqual(out_msg, session["msg"])

            nonce, eph_x, eph_y, eph_sec_key = session["msg_ctx"]
            self.assertEqual(
                sigma.nonce,
                nonce,
                "The field sigma.nonce should be set correctly.",
            )
            self.assertEqual(
                sigma.eph_x,
                eph_x,
                "The field sigma.eph_x should be set correctly.",
            )
            self.assertEqual(
                sigma.eph_y,
                eph_y,
                "The field sigma.eph_y should be set correctly.",
            )
            self.assertEqual(
                sigma.eph_sec_key,
                eph_sec_key,
                "The field sigma.eph_sec_key should be set correctly.",
            )


class TestsTask3(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(TEST_DATA_SESSIONS_PATH, "rb") as session_file:
            cls.sessions_public = pickle.load(session_file)
        with open(TEST_DATA_SESSIONS_PRIVATE_PATH, "rb") as session_file:
            cls.sessions_private = pickle.load(session_file)

    def test_parse_client_hello(self):
        for session in self.sessions_public:
            curve = ec_setup_test(session["ecdh_curve"])
            out = parse_client_hello(session["msg"], curve)
            self.assertTupleEqual(out[:-1], session["out_parse_client_hello"])
            self.assertTupleEqual(
                convert_ec_pub_bytes_test(out[-1]),
                session["out_parse_client_hello"][1:3],
            )

    def test_server_ecdsa_resp_pub(self):
        for session in self.sessions_public:
            sigma = create_test_sigma_with_session_data(
                session, role=ROLE_SERVER, offset=OFFSET_ROUND1
            )
            out_msg = sigma.server_ecdsa_resp(session["msg"])
            self.assertEqual(
                out_msg,
                session["msg_two"],
            )

            mac_key, client_sig_msg = session["msg_two_ctx"]

            self.assertEqual(
                sigma.mac_key,
                mac_key,
                "MAC key sigma.mac_key should be set correctly.",
            )
            self.assertEqual(
                sigma.client_key,
                session["server_key"][ROLE_CLIENT],
                "Shared client secret sigma.client_key should be set correctly.",
            )
            self.assertEqual(
                sigma.server_key,
                session["server_key"][ROLE_SERVER],
                "Shared server secret sigma.server_key should be set correctly.",
            )
            self.assertEqual(
                sigma.client_sig_msg,
                client_sig_msg,
                "Client signature message sigma.client_sig_msg should be set correctly.",
            )

    def test_server_ecdsa_resp_priv(self):
        for session in self.sessions_private:
            sigma = create_test_sigma_with_session_data(
                session, role=ROLE_SERVER, offset=OFFSET_ROUND1
            )
            out_msg = sigma.server_ecdsa_resp(session["msg"])
            self.assertEqual(
                out_msg,
                session["msg_two"],
                "Message should be created correctly",
            )

            mac_key, client_sig_msg, enc_key = session["msg_two_ctx"]

            self.assertEqual(
                sigma.mac_key,
                mac_key,
                "MAC key sigma.mac_key should be set correctly.",
            )
            self.assertEqual(
                sigma.client_key,
                session["server_key"][ROLE_CLIENT],
                "Shared client secret sigma.client_key should be set correctly.",
            )
            self.assertEqual(
                sigma.server_key,
                session["server_key"][ROLE_SERVER],
                "Shared server secret sigma.server_key should be set correctly.",
            )
            self.assertEqual(
                sigma.client_sig_msg,
                client_sig_msg,
                "Client signature message sigma.client_sig_msg should be set correctly.",
            )
            self.assertEqual(
                sigma.enc_key,
                enc_key,
                "ID encryption key sigma.enc_key should be set correctly.",
            )

class TestsTask4(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(TEST_DATA_SESSIONS_PATH, "rb") as session_file:
            cls.sessions_public = pickle.load(session_file)
        with open(TEST_DATA_SESSIONS_PRIVATE_PATH, "rb") as session_file:
            cls.sessions_private = pickle.load(session_file)

    def prepare_sigma(self, sigma, session):
        nonce, eph_x, eph_y, eph_sec_key = session["msg_ctx"]
        sigma.nonce = nonce
        sigma.eph_x = eph_x
        sigma.eph_y = eph_y
        sigma.eph_sec_key = eph_sec_key

    def test_parse_ecdsa_server_hello(self):
        for session in self.sessions_public:
            curve = ec_setup_test(session["ecdh_curve"])
            out = parse_ecdsa_server_hello(session["msg_two"], curve)
            self.assertTupleEqual(
                out[:4] + out[5:], session["out_parse_ecdsa_server_hello"]
            )
            self.assertTupleEqual(
                convert_ec_pub_bytes_test(out[4]),
                session["out_parse_ecdsa_server_hello"][2:4],
            )

    def test_parse_ecdsa_server_hello_id_hide(self):
        for session in self.sessions_private:
            curve = ec_setup_test(session["ecdh_curve"])
            out = parse_ecdsa_server_hello_id_hide(session["msg_two"], curve)
            self.assertTupleEqual(
                out[:3] + out[4:], session["out_parse_ecdsa_server_hello_id_hide"]
            )
            self.assertTupleEqual(
                convert_ec_pub_bytes_test(out[3]),
                session["out_parse_ecdsa_server_hello_id_hide"][1:3],
            )

    def test_parse_ecdsa_ptxt(self):
        for session in self.sessions_private:
            out = parse_ecdsa_ptxt(session["in_parse_ecdsa_ptxt"])
            self.assertTupleEqual(out, session["out_parse_ecdsa_ptxt"])

    def test_client_ecdsa_resp_pub(self):
        for session in self.sessions_public:
            sigma = create_test_sigma_with_session_data(
                session, role=ROLE_CLIENT, offset=OFFSET_ROUND2
            )
            self.prepare_sigma(sigma, session)
            out_msg, out_client_key, out_server_key = sigma.client_ecdsa_resp(
                session["msg_two"]
            )
            self.assertEqual(out_client_key, session["client_key"][ROLE_CLIENT])
            self.assertEqual(out_server_key, session["client_key"][ROLE_SERVER])

            self.assertEqual(
                out_msg,
                session["msg_three"],
                "Message should be correct",
            )

    def test_client_ecdsa_resp_priv(self):
        for session in self.sessions_private:
            sigma = create_test_sigma_with_session_data(
                session, role=ROLE_CLIENT, offset=OFFSET_ROUND2
            )
            self.prepare_sigma(sigma, session)
            out_msg, out_client_key, out_server_key = sigma.client_ecdsa_resp(
                session["msg_two"]
            )
            self.assertEqual(out_client_key, session["client_key"][ROLE_CLIENT])
            self.assertEqual(out_server_key, session["client_key"][ROLE_SERVER])

            self.assertEqual(
                out_msg,
                session["msg_three"],
                "Message should be correct.",
            )

    def test_client_ecdsa_resp_sig_error(self):
        for session in self.sessions_public + self.sessions_private:
            sigma = create_test_sigma_with_session_data(
                session, role=ROLE_CLIENT, offset=OFFSET_ROUND2
            )
            self.prepare_sigma(sigma, session)
            try:
                _ = sigma.client_ecdsa_resp(session["msg_two_sig_error"])
            except SigError:
                continue
            self.fail("Should throw a SigError if signature check fails")

    def test_client_ecdsa_resp_mac_error(self):
        for session in self.sessions_public + self.sessions_private:
            sigma = create_test_sigma_with_session_data(
                session, role=ROLE_CLIENT, offset=OFFSET_ROUND2
            )
            self.prepare_sigma(sigma, session)
            try:
                _ = sigma.client_ecdsa_resp(session["msg_two_mac_error"])
            except MacError:
                continue
            self.fail("Should throw a MacError if MAC check fails")

class TestsTask5(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(TEST_DATA_SESSIONS_PATH, "rb") as session_file:
            cls.sessions_public = pickle.load(session_file)
        with open(TEST_DATA_SESSIONS_PRIVATE_PATH, "rb") as session_file:
            cls.sessions_private = pickle.load(session_file)

    def prepare_sigma(self, sigma, session):
        if session["id_hide_flag"]:
            mac_key, client_sig_msg, enc_key = session["msg_two_ctx"]
            sigma.enc_key = enc_key
        else:
            mac_key, client_sig_msg = session["msg_two_ctx"]
        sigma.client_sig_msg = client_sig_msg
        sigma.mac_key = mac_key
        sigma.client_key = session["server_key"][ROLE_CLIENT]
        sigma.server_key = session["server_key"][ROLE_SERVER]

    def test_parse_ecdsa_client_resp(self):
        for session in self.sessions_public:
            out = parse_ecdsa_client_resp(session["msg_three"])
            self.assertTupleEqual(out, session["out_parse_ecdsa_client_resp"])

    def test_server_ecdsa_fin(self):
        for session in self.sessions_public + self.sessions_private:
            sigma = create_test_sigma_with_session_data(
                session, role=ROLE_SERVER, offset=OFFSET_ROUND2
            )
            self.prepare_sigma(sigma, session)
            out_client_key, out_server_key = sigma.server_ecdsa_fin(
                session["msg_three"]
            )
            self.assertEqual(out_client_key, session["server_key"][ROLE_CLIENT])
            self.assertEqual(out_server_key, session["server_key"][ROLE_SERVER])

    def test_server_ecdsa_fin_sig_error(self):
        for session in self.sessions_public + self.sessions_private:
            sigma = create_test_sigma_with_session_data(
                session, role=ROLE_SERVER, offset=OFFSET_ROUND2
            )
            self.prepare_sigma(sigma, session)
            try:
                _ = sigma.server_ecdsa_fin(session["msg_three_sig_error"])
            except SigError as s:
                continue
            self.fail("Should throw a SigError if signature check fails")

    def test_server_ecdsa_fin_mac_error(self):
        for session in self.sessions_public + self.sessions_private:
            sigma = create_test_sigma_with_session_data(
                session, role=ROLE_SERVER, offset=OFFSET_ROUND2
            )
            self.prepare_sigma(sigma, session)
            try:
                _ = sigma.server_ecdsa_fin(session["msg_three_mac_error"])
            except MacError:
                continue
            self.fail("Should throw a MacError if mac check fails")


if __name__ == "__main__":
    unittest.main()
