package dcr;

import java.math.BigInteger;
import schemes.RSA_Modulus;

/**
 * This class is a container class for a DCR challenge
 * <p>
 * A DCR challenge consists of two numbers: an RSA modulus N = P * Q and a
 * number z in Z/N^2 Z. A DCR challenge represents the problem of deciding if z
 * is an N-power in Z/N^2. I.e., if there is some y in Z/NZ s.t. y^N mod N^2 =
 * z.
 * <p>
 * I.e., a DCR challenge (N, z) represents the problem of deciding whether z
 * equals y^N mod N^2 for some y or if z was sampled uniformly and independently
 * at random from Z/N^2 Z.
 * <p>
 * A correct solution for this DCR challenge is a boolean value which is true
 * iff z is an N-residue modulo N^2, i.e. iff z = y^N mod N^2 for some y in Z/
 * N^2 Z.
 * <p>
 * Note that the member {@code modulus} of this class is not a number, but
 * rather an object of type {@code RSA_Modulus}. To get the real modulus N, you
 * need to call {modulus.getN()}.
 */
public class DCR_Challenge {
    /**
     * An element of Z/N^2 Z. z is either an N-residue modulo N^2, i.e. iff z = y^N
     * mod N^2, or it is a number which has been drawn uniformly at random from
     * Z/N^2 Z.
     */
    public final BigInteger z;
    /**
     * RSA modulus. Call modulus.getN() to get the real number modulus.
     */
    public final RSA_Modulus modulus;

    /**
     * Constructs a new DCR challenge.
     * 
     * @param z       An element of Z/N^2 Z
     * @param modulus specifies the modulus N resp. N^2 of this challenge.
     */
    public DCR_Challenge(BigInteger z, RSA_Modulus modulus) {
        this.z = z;
        this.modulus = modulus;
    }
}
