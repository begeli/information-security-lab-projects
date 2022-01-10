package rsafdh.eufcma;

import rsafdh.I_RSAFDH_EUF_Adversary;

/**
 * An interface for adversaries in the EUF-CMA security game of RSA-FDH.
 * 
 * An adaptive chosen-message-attacker will ask signing queries for arbitrary
 * messages and return a forged signature in the end, for which it has not asked
 * a signing query.
 * 
 * When you call the {@code run} method of this adversary, it will use
 * {@code getPK} at the beginning of the game to receive a verification key.
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
public interface I_RSAFDH_EUFCMA_Adversary extends I_RSAFDH_EUF_Adversary<I_RSAFDH_EUFCMA_Challenger> {

}
