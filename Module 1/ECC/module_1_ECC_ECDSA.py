import math
import random
import warnings
import hashlib

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

# Function to map a message to a bit string
def hash_message_to_bits(msg):
    h = hashlib.sha256()
    h.update(msg.encode())
    h_as_bits = ''.join(format(byte, '08b') for byte in h.digest())
    return h_as_bits 

# Function to map a truncated bit string to an integer modulo q
def bits_to_int(h_as_bits, q):
    val = 0
    len = int(math.log(q, 2) + 1)
    for i in range(len):
        val = val * 2
        if(h_as_bits[i] == '1'):
            val = val + 1
    return val % q

# An elliptic curve is represented as an object of type Curve. 
# We use the short Weierstrass form of representation.
class Curve(object):

    def __init__(self, a, b, p, P_x, P_y, q):
        self.a = a
        self.b = b
        self.p = p
        self.P_x = P_x
        self.P_y = P_y
        self.q = q

    def is_singular(self):
        return (4 * self.a**3 + 27 * self.b**2) % self.p == 0

    def on_curve(self, x, y):
        return (y**2 - x**3 - self.a * x - self.b) % self.p == 0

    def is_equal(self, other):
        if not isinstance(other, Curve):
            return False
        return self.a == other.a and self.b == other.b and self.p == other.p

# A point at infinity on an elliptic curve is represented separately as an object of type PointInf. 
# We make this distinction between a point at infinity and a regular point purely for the ease of implementation.
class PointInf(object):

    def __init__(self, curve):
        self.curve = curve

    def is_equal(self, other):
        if not isinstance(other, PointInf):
            return False
        return self.curve.is_equal(other.curve)
    
    def negate(self):
        # A function that negates a PointInf object.
        # Ths is an optional extension and is not evaluated
        # Point at infinity is its own inverse
        return PointInf(self.curve)

    def double(self):
        # A function that doubles a PointInf object.
        # O + O = O
        return PointInf(self.curve)

    def add(self, other):
        # Should probably check if the other point is in the same curve as the current point
        # A function that adds a Point object (or a PointInf object) to a PointInf object.
        # See below for the description of a Point object
        # Make sure to output the correct kind of object depending on whether "other" is a Point object or a PointInf object 
        if not self.curve.is_equal(other.curve):
            raise ValueError("Both points should be in the same curve.")

        if type(other) is PointInf:
            return PointInf(self.curve) # TODO: Can point at infinities have different curves - if so, what happens to the new curve
        else:
            return Point(other.curve, other.x, other.y)


# A point on an elliptic curve is represented as an object of type Point.
class Point(object):

    def __init__(self, curve, x, y):
        self.curve = curve
        self.x = x
        self.y = y
        self.p = self.curve.p
        self.on_curve = True
        if not self.curve.on_curve(self.x, self.y):
            warnings.warn("Point (%d, %d) is not on curve \"%s\"" % (self.x, self.y, self.curve))
            self.on_curve = False

    def is_equal(self, other):
        if not isinstance(other, Point):
            return False
        return self.curve.is_equal(other.curve) and self.x == other.x and self.y == other.y
    
    def negate(self):
        # A function that negates a Point object and returns the resulting Point object
        return Point(self.curve, self.x, self.p - self.y) # TODO: should this y be -y % p

    def double(self):
        # A function that doubles a Point object and returns the resulting Point object
        # If self is equal to its inverse, i.e. y = 0
        if self.is_equal(self.negate()): # TODO: Check this
            return PointInf(self.curve)

        slope = (3 * (self.x ** 2) + self.curve.a) * mod_inv(2 * self.y, self.p)
        x_new = ((slope ** 2) - (2 * self.x)) % self.p
        y_new = (slope * (self.x - x_new) - self.y) % self.p

        return Point(self.curve, x_new, y_new)

    def add(self, other):
        # A function that adds a Point object (or a PointInf object) to the current Point object and returns the resulting Point object
        # Should probably check if the other point is in the same curve as the current point
        if not self.curve.is_equal(other.curve):
            raise ValueError("Both points should be in the same curve.")

        # Edge case 1: Other is Point at Infinity
        if type(other) is PointInf:
            return other.add(self)

        # Edge case 2: Other point is equal to self
        if other.is_equal(self):
            return self.double()

        # Edge case 3: Other point is the inverse of self
        if other.is_equal(self.negate()): # TODO: check negate implementation is correct
            return PointInf(self.curve)

        # Edge case 4: Other has the same x coordinate but different y coordinate
        if other.x == self.x and other.y != self.y:
            return PointInf(self.curve)

        slope = (other.y - self.y) * mod_inv(other.x - self.x, self.p)
        x_3 = (slope ** 2 - self.x - other.x) % self.p
        y_3 = (slope * (self.x - x_3) - self.y) % self.p

        return Point(self.curve, x_3, y_3)

    def scalar_multiply(self, scalar):
        # A function that performs a scalar multiplication on the current Point object and returns the resulting Point object 
        # Make sure to check that the scalar is of type int or long
        # Not "constant-time"
        if type(scalar) is not int: # TODO: is there a separate long type
            raise ValueError("Scalar should be of type int")

        binary = bin(scalar)[2:] 
        res = PointInf(self.curve) # What should we return if scalar is 0
        for i in range(len(binary)):
            res = res.double()
            if binary[i] == "1":
                res = res.add(self)

        return res
    
    def scalar_multiply_Montgomery_Ladder(self, scalar):
        # A function that performs a "constant-time" scalar multiplication on the current Point object and returns the resulting Point object 
        # Make sure to check that the scalar is of type int
        if type(scalar) is not int: # TODO: is there a separate long type
            raise ValueError("Scalar should be of type int")

        binary = bin(scalar)[2:]
        R_0 = PointInf(self.curve)
        R_1 = Point(self.curve, self.x, self.y)
        for i in range(len(binary)):
            if binary[i] == "0":
                R_1 = R_1.add(R_0)
                R_0 = R_0.double()
            else:
                R_0 = R_0.add(R_1)
                R_1 = R_1.double()

        return R_0

# The parameters for an ECDSA scheme are represented as an object of type ECDSA_Params
class ECDSA_Params(object):
    def __init__(self, a, b, p, P_x, P_y, q):
        self.p = p
        self.q = q
        self.curve = Curve(a, b, p, P_x, P_y, q)
        self.P = Point(self.curve, P_x, P_y)


def KeyGen(params):
    # A function that takes as input an ECDSA_Params object and outputs the key pair (x, Q)
    x = random.randint(1, params.q - 1)
    Q = params.P.scalar_multiply(x)

    return (x, Q)

def Sign_FixedNonce(params, k, x, msg):
    # A function that takes as input an ECDSA_Params object, a fixed nonce k, a signing key x, and a message msg, and outputs a signature (r, s)
    h_as_bits = hash_message_to_bits(msg)
    h = bits_to_int(h_as_bits, params.q)
    k_P = params.P.scalar_multiply(k)
    r = k_P.x % params.q
    s = (mod_inv(k, params.q) * (h + x * r)) % params.q

    return (r, s)

def Sign(params, x, msg):
    # A function that takes as input an ECDSA_Params object, a signing key x, and a message msg, and outputs a signature (r, s)
    # The nonce is to be generated uniformly at random in the appropriate range

    # Take len(q) MSBs of H(m), cast to int, reduce mod q
    h_as_bits = hash_message_to_bits(msg)
    h = bits_to_int(h_as_bits, params.q)

    while True:
        k = random.randint(1, params.q - 1)
        k_P = params.P.scalar_multiply(k)

        # [k]P is a point on E; its x-coord is in F_p; we consider that as an integer and reduce mod q
        r = k_P.x % params.q
        s = (mod_inv(k, params.q) * (h + x * r)) % params.q

        # Should satisfy this condition on the first try with high probability
        if r != 0 and s != 0:
            break

    return (r, s)

def Verify(params, Q, msg, r, s):
    # A function that takes as input an ECDSA_Params object, a verification key Q, a message msg, and a signature (r, s)
    # The output should be either 0 (indicating failure) or 1 (indicating success)

    # Check 1 <= r < q and 1 <= s < q
    if r not in range(1, params.q):
        return 0
    if s not in range(1, params.q):
        return 0

    h_as_bits = hash_message_to_bits(msg)
    h = bits_to_int(h_as_bits, params.q)
    w = mod_inv(s, params.q)

    u_1 = (w * h) % params.q
    u_2 = (w * r) % params.q

    u_1_P = params.P.scalar_multiply(u_1)
    u_2_Q = Q.scalar_multiply(u_2)
    Z = u_1_P.add(u_2_Q)

    if Z.x % params.q == r:
        return 1
    else:
        return 0


from module_1_ECC_ECDSA_tests import run_tests
run_tests(ECDSA_Params, Point, KeyGen, Sign, Sign_FixedNonce, Verify)
