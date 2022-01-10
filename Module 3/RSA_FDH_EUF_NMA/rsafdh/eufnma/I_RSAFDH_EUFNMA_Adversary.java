package rsafdh.eufnma;

import rsafdh.I_RSAFDH_EUF_Adversary;

/**
 * An interface for adversaries in the EUF-NMA security game of RSA-FDH.
 * 
 * A no-message-attacker forges a signature without making any signature
 * queries.
 * 
 * In a run of the security game, adversary will call the {@code getPK()} method
 * of its challenger to get the public key of the RSA-FDH scheme to which it
 * will forge a signature.
 * 
 * @author Julia
 */
public interface I_RSAFDH_EUFNMA_Adversary extends I_RSAFDH_EUF_Adversary<I_RSAFDH_EUFNMA_Challenger> {

}
