package rsafdh;

import java.math.BigInteger;

import schemes.RSA_Modulus;

/**
 * The public key resp. verification key of the RSA-FDH signing scheme. An
 * RSA-FDH EUF adversary will always ask his challenger for this verification
 * key.
 * 
 * @author Julia
 */
public class RSAFDH_PK {
    /**
     * The RSA modulus which is used by the RSA-FDH signing scheme. To get the
     * number N, call {@code modulus.getN()}.
     */
    public final RSA_Modulus modulus;
    /**
     * The exponent used for verifiying signatures. For a valid signatur sig, it
     * must hold sig^exponent mod N == h, where h is the hash value of the message
     * to be signed.
     */
    public final BigInteger exponent;

    /**
     * Contructs a new verification key for RSA-FDH.
     * 
     * @param modulus  The RSA modulus which is used by the RSA-FDH signing scheme.
     * @param exponent The exponent used for verifiying signatures. For a valid
     *                 signatur sig, it must hold sig^exponent mod N == h, where h
     *                 is the hash value of the message to be signed.
     */
    public RSAFDH_PK(RSA_Modulus modulus, BigInteger exponent) {
        this.modulus = modulus;
        this.exponent = exponent;
    }
}