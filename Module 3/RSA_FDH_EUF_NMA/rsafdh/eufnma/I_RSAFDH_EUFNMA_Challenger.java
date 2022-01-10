package rsafdh.eufnma;

import rsafdh.I_RSAFDH_EUF_Challenger;
import rsafdh.RSAFDH_PK;

/**
 * An RSA-FDH EUF-NMA challenger plays the EUF-NMA security game of the RSA-FDH
 * signing scheme with implementations of the {@code I_RSAFDH_EUFNMA_Adversary}
 * interface.
 * 
 * Challengers of this kind only offer their adversaries a method to output a
 * public resp. verification key and expect the adversaries to forge a signature
 * with respect to that public key.
 * 
 * @author Julia
 */
public interface I_RSAFDH_EUFNMA_Challenger extends I_RSAFDH_EUF_Challenger {
    /**
     * The RSA-FDH EUF-NMA adversary will call this method to get the public key of the
     * RSA-FDH scheme to which it will forge a signature.
     * 
     * In a run, this method should always return the same public key, no matter how
     * often it has been asked.
     * 
     * @return a verification key for the RSA-FDH signing scheme.
     */
    public RSAFDH_PK getPk();
}
