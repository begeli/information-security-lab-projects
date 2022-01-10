package rsafdh;

import basics.IAdversary;
import java.math.BigInteger;

/**
 * This interface captures the functionality of an adversary in the EUF-security
 * game of the signature scheme RSA-FDH.
 * 
 * Adversaries which implement this interface will always ask their challenger
 * for multiple hash queries for some messages (the number of hash queries this
 * adversary will ask is specified by {@code numHashQueries()}).
 * 
 * An EUF adversary will at the end of the game always come up with an RSAFDH
 * Solution. That is, it will come up with a message m and a forged signature
 * for this message m where it is guaranteed that this adversary has never seen
 * a signature for the message m before.
 * <p>
 * The type of the challenger and the mode of the adversary (CMA, NMA, naCMA) is
 * yet to be specified by the parameter C.
 * <p>
 * If you are a reduction using this adversary, then remember that you need to
 * play the corresponding security game correctly with this adversary.
 * Otherwise, this adversary may only have a negligible advantage in forging a
 * correct signature. Further, note that you may call the run method of your
 * adversaries at most once.
 * 
 * 
 * @param C the type of the RSAFDH EUF Challenger with which this adversary will
 *          play the security game. C determines if the adversary is in the
 *          security game fully adaptive (CMA), non-adaptive (naCMA) or may not
 *          even see signatures (NMA).
 * 
 * @author Julia
 */
public interface I_RSAFDH_EUF_Adversary<C extends I_RSAFDH_EUF_Challenger> extends IAdversary<C, RSAFDH_Solution> {
    /**
     * A helper method four you which can verify the correctness of a signature.
     * Given a public key of an RSA-FDH scheme, a hash value of a message m and a
     * signature, this method returns true iff signature is a correct signature for
     * the message with hash value hash under the given public key.
     * 
     * @param pk        the public key resp. verification key of the RSA-FDH scheme.
     * @param hash      the hash value of the message which is supposed to be
     *                  signed.
     * @param signature the signature to be verified.
     * @return true if the signature is valid, false otherwise.
     */
    default boolean verifySig(RSAFDH_PK pk, BigInteger hash, BigInteger signature) {
        if (signature == null)
            return false;
        return signature.modPow(pk.exponent, pk.modulus.getN()).equals(hash);
    }

    /**
     * Specifies how many hash queries this adversary may ask. I.e., this number
     * determines how many times this adversary will call the
     * {@code hash(String message)} method of the given challenger.
     * 
     * @return the number of messages for which this adversary will ask hash values
     *         for.
     */
    int numHashQueries();

    /**
     * Returns true iff the run method of this adversary has been called at most
     * once.
     * 
     * @return true iff the run method of this adversary has been called at most
     *         once.
     */
    boolean isTight();
}