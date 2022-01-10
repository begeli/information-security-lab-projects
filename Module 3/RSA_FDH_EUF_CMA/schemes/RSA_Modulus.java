package schemes;

import java.math.BigInteger;

/**
 * class for RSA modulus, encapsulates the RSA modulus
 * 
 * @author Julia
 */
public final class RSA_Modulus {
    /**
     * factor p of the rsa modulus
     */
    private final BigInteger p;
    /**
     * factor q of the rsa modulus
     */
    private final BigInteger q;
    /**
     * product of the two factors
     */
    private final BigInteger N;
    /**
     * phi(N) = (p-1) * (q-1)
     */
    private final BigInteger phiN;

    /**
     * construct a new RSA modulus using two (hopefully prime) factors (other fields
     * are filled in automatically)
     * 
     * @param p factor p
     * @param q factor q
     */
    public RSA_Modulus(BigInteger p, BigInteger q) {
        this.p = p;
        this.q = q;
        this.N = p.multiply(q);
        this.phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    /**
     * get the modulus
     * 
     * @return the public modulus N
     */
    public BigInteger getN() {
        return this.N;
    }

    /**
     * get factor p
     * 
     * @return the (secret) factor p
     */
    BigInteger getP() {
        return this.p;
    }

    /**
     * get factor q
     * 
     * @return the (secret) factor q
     */
    BigInteger getQ() {
        return this.q;
    }

    /**
     * get phi(N)
     * 
     * @return phi(N)
     */
    BigInteger getPhiN() {
        return this.phiN;
    }
}
