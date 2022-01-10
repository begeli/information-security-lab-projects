package rsafdh.eufcma;

import java.math.BigInteger;

import rsafdh.I_RSAFDH_EUF_Challenger;
import rsafdh.RSAFDH_PK;

/**
 * An RSA-FDH EUF-CMA challenger plays the EUF-CMA security game of the RSA-FDH
 * signing scheme with implementations of the {@code I_RSAFDH_EUFCMA_Adversary}
 * interface.
 * 
 * Challengers of this kind offer two addtional methods: {@code getPK} and
 * {@code sign}. When run, an EUF-naCMA adversary will use {@code getPK} at the
 * beginning of the game to receive a verification key.
 * 
 * After that, it may call multiple times {@code sign} to receive signatures to
 * messages. It will assume that each signature it receives is a valid signature
 * for the message it gave.
 * 
 * If the signatures are correct and the EUF-CMA game has been played correctly
 * with the adversary, it will return in its run method a forged signature to a
 * message for which it has not called the {@code sign} method.
 * 
 * @author Julia
 */
public interface I_RSAFDH_EUFCMA_Challenger extends I_RSAFDH_EUF_Challenger {

    /**
     * The RSA-FDH EUF-CMA will call this method to get the public key of the
     * RSA-FDH scheme to which it will forge a signature.
     * 
     * In a run, this method should always return the same public key, no matter how
     * often it has been asked.
     * 
     * @return a verification key for the RSA-FDH signing scheme.
     */
    public RSAFDH_PK getPk();

    /**
     * The challenger needs to return here a correct signature of message under the
     * public key it returned in {@code getPK()}.
     * 
     * @param message the message to be signed.
     * @return a signature for the given message under the verification key given in
     *         {@code getPK()}.
     */
    public BigInteger sign(String message);

}
