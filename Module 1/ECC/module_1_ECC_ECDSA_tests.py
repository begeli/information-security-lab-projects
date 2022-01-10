import unittest
import filecmp


N_SAMPLES = 100
N_SAMPLES_2 = 10


class TestECC(unittest.TestCase):

    def test_scalar_mult(self):
        with self.subTest(f"Scalar multiplication"):
            self.assertTrue(filecmp.cmp(
                'unit_test_scalar_mult_outputs_temp.txt', 'unit_test_scalar_mult_outputs.txt'))

    def test_point_addition(self):
        with self.subTest(f"Point addition"):
            self.assertTrue(filecmp.cmp(
                'unit_test_point_addition_outputs_temp.txt', 'unit_test_point_addition_outputs.txt'))

    def test_sign_fixed_nonce(self):
        with self.subTest(f"Sign (fixed nonce)"):
            self.assertTrue(filecmp.cmp(
                'unit_test_sign_fixed_nonce_outputs_temp.txt', 'unit_test_sign_fixed_nonce_outputs.txt'))

    def test_verify_outputs(self):
        with self.subTest(f"Verify"):
            self.assertTrue(filecmp.cmp(
                'unit_test_verify_outputs_temp.txt', 'unit_test_verify_outputs.txt'))

    def test_sign_and_verify(self):
        with self.subTest(f"Sign and Verify"):
            self.assertTrue((test_sign_and_verify() == 0))


def generate_outputs(Point, Sign_FixedNonce, Verify):

    # Unit testing for scalar multiplication
    scalar_mult_out = []

    with open('unit_test_scalar_mult_inputs.txt', 'r') as filehandle:
        for i in range(N_SAMPLES):
            line_space = filehandle.readline()
            scalar_mult_inp = filehandle.readline().split()
            k = int(scalar_mult_inp[0])
            P1_x = int(scalar_mult_inp[1])
            P1_y = int(scalar_mult_inp[2])
            P1 = Point(nistp256_params.curve, P1_x, P1_y)
            P2 = P1.scalar_multiply(k)
            scalar_mult_out.append((P2.x, P2.y))

    with open('unit_test_scalar_mult_outputs_temp.txt', 'w') as filehandle:
        for (P2_x, P2_y) in scalar_mult_out:
            filehandle.write('\n%d %d\n' % (P2_x, P2_y))

    # Unit testing for point addition
    point_add_out = []

    with open('unit_test_point_addition_inputs.txt', 'r') as filehandle:
        for i in range(N_SAMPLES):
            line_space = filehandle.readline()
            point_add_inp = filehandle.readline().split()
            P1_x = int(point_add_inp[0])
            P1_y = int(point_add_inp[1])
            P2_x = int(point_add_inp[2])
            P2_y = int(point_add_inp[3])
            P1 = Point(nistp256_params.curve, P1_x, P1_y)
            P2 = Point(nistp256_params.curve, P2_x, P2_y)
            P3 = P1.add(P2)
            point_add_out.append((P3.x, P3.y))

    with open('unit_test_point_addition_outputs_temp.txt', 'w') as filehandle:
        for (P3_x, P3_y) in point_add_out:
            filehandle.write('\n%d %d\n' % (P3_x, P3_y))

    # Unit testing for sign with fixed nonce
    sign_fixed_nonce_out = []
    msg = "Unit Test for Sign with Fixed Nonce"

    with open('unit_test_sign_fixed_nonce_inputs.txt', 'r') as filehandle:
        for i in range(N_SAMPLES):
            line_space = filehandle.readline()
            sign_fixed_nonce_inp = filehandle.readline().split()
            k = int(sign_fixed_nonce_inp[0])
            x = int(sign_fixed_nonce_inp[1])
            r, s = Sign_FixedNonce(nistp256_params, k, x, msg)
            sign_fixed_nonce_out.append((r, s))

    with open('unit_test_sign_fixed_nonce_outputs_temp.txt', 'w') as filehandle:
        for (r, s) in sign_fixed_nonce_out:
            filehandle.write('\n%d %d\n' % (r, s))

    # Unit testing for verify

    verify_out = []
    msg = "Unit Test for Verification"

    with open('unit_test_verify_inputs.txt', 'r') as filehandle:
        for i in range(N_SAMPLES):
            line_space = filehandle.readline()
            verify_inp = filehandle.readline().split()
            Q_x = int(verify_inp[0])
            Q_y = int(verify_inp[1])
            r = int(verify_inp[2])
            s = int(verify_inp[3])
            Q = Point(nistp256_params.curve, Q_x, Q_y)
            verify_out.append(Verify(nistp256_params, Q, msg, r, s))

    with open('unit_test_verify_outputs_temp.txt', 'w') as filehandle:
        for bit in verify_out:
            filehandle.write('\n%d\n' % bit)

_KeyGen = None
_Sign = None
_Verify = None
nistp256_params = None


def test_sign_and_verify():
    # Testing for sign + verify
    msg = "Unit Test for Sign and Verify Consistency"
    cnt_failure = 0

    for i in range(N_SAMPLES_2):
        x, Q = _KeyGen(nistp256_params)
        for j in range(N_SAMPLES_2):
            r, s = _Sign(nistp256_params, x, msg)
            if(_Verify(nistp256_params, Q, msg, r, s) == 0):
                cnt_failure = cnt_failure + 1

    return cnt_failure


def run_tests(ECDSA_Params, Point, KeyGen, Sign, Sign_FixedNonce, Verify):
    global _KeyGen
    global _Sign
    global _Verify
    global nistp256_params

    _KeyGen = KeyGen
    _Sign = Sign
    _Verify = Verify

    # Parameters for NIST P-256:
    a   = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    b   = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    p   = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    P_x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
    P_y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    q   = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    nistp256_params = ECDSA_Params(a, b, p, P_x, P_y, q)

    generate_outputs(Point, Sign_FixedNonce, Verify)

    suite = unittest.TestSuite()
    suite.addTest(TestECC('test_scalar_mult'))
    suite.addTest(TestECC('test_point_addition'))
    suite.addTest(TestECC('test_sign_fixed_nonce'))
    suite.addTest(TestECC('test_verify_outputs'))
    suite.addTest(TestECC('test_sign_and_verify'))
    runner = unittest.TextTestRunner()
    runner.run(suite)
