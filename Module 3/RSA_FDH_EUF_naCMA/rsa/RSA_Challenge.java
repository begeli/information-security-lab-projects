package rsa;

import java.math.BigInteger;

import schemes.RSA_Modulus;

/**
 * This class is a container class for an RSA challenge
 * <p>
 * An RSA challenge consists of three numbers: an RSA modulus N, a number y in
 * Z/NZ and a number e. An RSA challenge represents the problem of computing an
 * e-th root of y modulo N. I.e. computing a number x s.t. x^e mod N = y.
 * <p>
 * Note that the member {@code modulus} of this class is not a number, but
 * rather an object of type {@code RSA_Modulus}. To get the real modulus N, you
 * need to call {modulus.getN()}.
 * 
 * @author Nico
 */
public class RSA_Challenge {
    /**
     * RSA modulus. Call modulus.getN() to get the real number modulus.
     */
    public final RSA_Modulus modulus;
    /**
     * RSA challenge value
     */
    public final BigInteger y;
    /**
     * exponent
     */
    public final BigInteger e;

    /**
     * Constructs a new RSA challenge. The challenge consists of computing an e-th
     * root of y modulo N.
     * 
     * @param modulus specifies the modulus N of this challenge.
     * @param y       the challenge value
     * @param e       the exponent
     */
    public RSA_Challenge(RSA_Modulus modulus, BigInteger y, BigInteger e) {
        this.modulus = modulus;
        this.y = y;
        this.e = e;
    }
}