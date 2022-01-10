import math
import operator
import random

import numpy.linalg
from fpylll import LLL
from fpylll import BKZ
from fpylll import IntegerMatrix
from fpylll import CVP
from fpylll import SVP
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


# Euclidean algorithm for gcd computation
def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


# Modular inversion computation
def mod_inv(a, p):
    if a < 0:
        return p - mod_inv(-a, p)
    g, x, y = egcd(a, p)
    if g != 1:
        raise ArithmeticError("Modular inverse does not exist")
    else:
        return x % p


def check_x(x, Q):
    """ Given a guess for the secret key x and a public key Q = [x]P,
        checks if the guess is correct.

        :params x:  secret key, as an int
        :params Q:  public key, as a tuple of two ints (Q_x, Q_y)
    """
    x = int(x)
    if x <= 0:
        return False
    Q_x, Q_y = Q
    sk = ec.derive_private_key(x, ec.SECP256R1())
    pk = sk.public_key()
    xP = pk.public_numbers()
    return xP.x == Q_x and xP.y == Q_y

def recover_x_known_nonce(k, h, r, s, q):
    # The function is given the nonce k, (h, r, s) and the base point order q
    # The function should compute and return the secret signing key x
    x = (s * k - h) * mod_inv(r, q) % q

    return x

def recover_x_repeated_nonce(h_1, r_1, s_1, h_2, r_2, s_2, q):
    # The function is given the (hashed-message, signature) pairs (h_1, r_1, s_1) and (h_2, r_2, s_2) generated using the same nonce
    # The function should compute and return the secret signing key x
    x = (h_1 * s_2 - h_2 * s_1) * mod_inv(r_2 * s_1 - r_1 * s_2, q) % q

    return x


def MSB_to_Padded_Int(N, L, list_k_MSB):
    # Let a is the integer represented by the L most significant bits of the nonce k
    # The function should return a.2^{N - L} + 2^{N -L -1}
    a = LSB_to_Int(list_k_MSB)

    return a * 2**(N - L) + 2**(N - L - 1)

def LSB_to_Int(list_k_LSB):
    # Let a be the integer represented by the L least significant bits of the nonce k
    # The function should return a
    val = 0
    for bit in list_k_LSB:
        val *= 2
        if bit == 1:
            val += 1

    return val

def setup_hnp_single_sample(N, L, list_k_MSB, h, r, s, q, givenbits="msbs", algorithm="ecdsa"):
    # A function that sets up a single instance for the hidden number problem (HNP)
    # The function is given a list of the L most significant bts of the N-bit nonce k, along with (h, r, s) and the base point order q
    # The function should return (t, u)
    # In the case of EC-Schnorr, r may be set to h
    t = 0
    u = 0
    if algorithm == "ecdsa":
        if givenbits == "msbs":
            s_inv = mod_inv(s, q)
            t = (r * s_inv) % q
            z = (h * s_inv) % q
            u = MSB_to_Padded_Int(N, L, list_k_MSB) - z % q
        elif givenbits == "lsbs":
            s_inv = mod_inv(s, q)
            two_to_L_inv = mod_inv(2**L, q)
            a = LSB_to_Int(list_k_MSB)

            t = (r * s_inv * two_to_L_inv) % q
            z = (h * s_inv) % q
            u = ((a - z) * two_to_L_inv) % q
    elif algorithm == "ecschnorr":
        if givenbits == "msbs":
            t = h % q
            u = (MSB_to_Padded_Int(N, L, list_k_MSB) - s) % q
        elif givenbits == "lsbs":
            two_to_L_inv = mod_inv(2 ** L, q)
            a = LSB_to_Int(list_k_MSB)

            t = h * two_to_L_inv % q
            u = (a - s) * two_to_L_inv % q

    return (t, u)

def setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits="msbs", algorithm="ecdsa"):
    # A function that sets up n = num_Samples many instances for the hidden number problem (HNP)
    # For each instance, the function is given a list the L most significant bits of the N-bit nonce k, along with (h, r, s) and the base point order q
    # The function returns a list of t values and a list of u values computed as described in the lectures
    # In the case of EC-Schnorr, list_r may be set to list_h
    list_t = []
    list_u = []
    for i in range(num_Samples):
        (t, u) = setup_hnp_single_sample(N, L, listoflists_k_MSB[i], list_h[i], list_r[i], list_s[i], q, givenbits, algorithm)
        list_t.append(t)
        list_u.append(u)

    return (list_t, list_u)

def hnp_to_cvp(N, L, num_Samples, list_t, list_u, q):
    # A function that takes as input an instance of HNP and converts it into an instance of the closest vector problem (CVP)
    # The function is given as input a list of t values, a list of u values and the base point order q
    # The function returns the CVP basis matrix B (to be implemented as a nested list) and the CVP target vector u (to be implemented as a list)
    scale_factor = 2**(L + 1) # We didn't use N. Should the scale factor be 2**(N + L + 1) or maybe 2**N (so. last value becomes 2**(N - L - 1))

    # Create and scale basis matrix (n+1 x n+1)
    cvp_basis_B = []
    for row in range(num_Samples):
        row_vec = []
        for col in range(num_Samples + 1):
            row_vec.append(scale_factor * q if row == col else 0)
        cvp_basis_B.append(row_vec)
    # Append last row
    row_vec = [scale_factor * t for t in list_t]
    row_vec.append(1)
    cvp_basis_B.append(row_vec)

    # Create and scale target vector
    cvp_list_u = [scale_factor * u for u in list_u]
    cvp_list_u.append(0)

    return (cvp_basis_B, cvp_list_u)

def cvp_to_svp(N, L, num_Samples, cvp_basis_B, cvp_list_u):
    # A function that takes as input an instance of CVP and converts it into an instance of the shortest vector problem (SVP)
    # The function is given as input a CVP basis matrix B and the CVP target vector u
    # The function uses the Kannan embedding technique to output the corresponding SVP basis matrix B' of apropriate dimensions.
    # The SVP basis matrix B' should again be implemented as a nested list
    scale_factor = 2**(L + 1)
    #M = int((num_Samples + 2) ** (0.5) * 2 ** (N - L - 1) * 0.5)

    exponent = (num_Samples * N - L - 1) / (num_Samples + 2)
    M = int((num_Samples + 2)**(0.5) * 2**(exponent) * 0.5)

    # Create the scaled SVP basis
    svp_basis_B = []
    for row in cvp_basis_B:
        row_vec = [col for col in row]
        row_vec.append(0)
        svp_basis_B.append(row_vec)
    row_vec = [u for u in cvp_list_u]
    row_vec.append(M * scale_factor)
    svp_basis_B.append(row_vec)

    return svp_basis_B


def solve_cvp(cvp_basis_B, cvp_list_u):
    # A function that takes as input an instance of CVP and solves it using in-built CVP-solver functions from the fpylll library
    # The function is given as input a CVP basis matrix B and the CVP target vector u
    # The function outputs the solution vector v (to be implemented as a list)
    limitingDim = 25 # picked randomly

    # Use a diffrent reduction algorithm based on the dimension of the basis
    if cvp_basis_B.ncols < limitingDim:
        lll = LLL()
        cvp_basis_B = lll.reduction(cvp_basis_B)
    else:
        block_size = 10
        bkz = BKZ()
        cvp_basis_B = bkz.reduction(cvp_basis_B, BKZ.Param(block_size))

    # Solve the CVP problem
    cvp = CVP()
    v = cvp.closest_vector(cvp_basis_B, cvp_list_u)

    return v


def solve_svp(svp_basis_B):
    # A function that takes as input an instance of SVP and solves it using in-built SVP-solver functions from the fpylll library
    # The function is given as input the SVP basis matrix B
    # The function outputs a list of candidate vectors that may contain x as a coefficient
    candidate_count = 5

    # Solve the SVP problem
    svp = SVP()
    svp.shortest_vector(svp_basis_B)

    # Collect the shortyish vectors that might contain x
    candidate_vectors = []
    for i in range(candidate_count):
        short_vector = [num for num in svp_basis_B[i]]
        candidate_vectors.append(short_vector)

    return candidate_vectors


def recover_x_partial_nonce_CVP(Q, N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits="msbs", algorithm="ecdsa"):
    # "Repeated nonces" cryptanalytic attack on ECDSA and EC-Schnorr using the in-built CVP-solver functions from the fpylll library
    list_t, list_u = setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits, algorithm)
    cvp_basis_B, cvp_list_u = hnp_to_cvp(N, L, num_Samples, list_t, list_u, q)

    # Convert basis matrix B into an integer matrix
    cvp_basis_B = IntegerMatrix.from_matrix(A=cvp_basis_B)
    v_List = solve_cvp(cvp_basis_B, cvp_list_u)

    # The function should recover the secret signing key x from the output of the CVP solver and return it
    x = v_List[num_Samples]

    # Check if we got the correct signing key or x - q as our result
    if check_x(x, Q):
        return x
    else:
        return x + q


def recover_x_partial_nonce_SVP(Q, N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits="msbs", algorithm="ecdsa"):
    # "Repeated nonces" cryptanalytic attack on ECDSA and EC-Schnorr using the in-built SVP-solver functions from the fpylll library
    list_t, list_u = setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits, algorithm)
    cvp_basis_B, cvp_list_u = hnp_to_cvp(N, L, num_Samples, list_t, list_u, q)
    svp_basis_B = cvp_to_svp(N, L, num_Samples, cvp_basis_B, cvp_list_u)

    # Convert to Integer matrix
    svp_basis_B = IntegerMatrix.from_matrix(A=svp_basis_B)
    list_of_f_List = solve_svp(svp_basis_B)

    x = 0
    for row in list_of_f_List:
        candidate = cvp_list_u[num_Samples] - row[num_Samples]

        try:
            if check_x(candidate, Q):
                x = candidate
                break
        except:
            x = 0

        try:
            if check_x(candidate + q, Q):
                x = candidate + q
                break
        except:
            continue

    # The function should recover the secret signing key x from the output of the SVP solver and return it
    return x



# testing code: do not modify

from module_1_ECDSA_Cryptanalysis_tests import run_tests

run_tests(recover_x_known_nonce,
    recover_x_repeated_nonce,
    recover_x_partial_nonce_CVP,
    recover_x_partial_nonce_SVP
)