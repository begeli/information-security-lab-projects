package rsafdh.eufnacma;

import rsafdh.I_RSAFDH_EUF_Adversary;

/**
 * An interface for adversaries in the EUF-NMA security game of RSA-FDH.
 * 
 * A non-adaptive chosen-message-attacker will submit a list of messages for
 * which it will ask signatures and a challenge message for which it will forge
 * a signature.
 * 
 * When you call the method {@code run} of this adversary, it will use the
 * {@code submitMessagesAndGetPK} method of the challenger at the beginning of
 * the game to commit itself to a list of messages, for which it will ask
 * signatures, and a challenge message for which it will forge a signature
 * before seeing the verification key.
 * 
 * After calling {@code submitMessagesAndGetPK}, the adversary will call
 * {@code getSignatures} to get the signatures of the messages to which it
 * commited itself in its {@code submitMessagesAndGetPK} call. If the signatures
 * are correct and the EUF-naCMA game has been played correctly with the
 * adversary, it will return a forged signature to the challenge message to
 * which it committed itself.
 * 
 * @author Julia
 */
public interface I_RSAFDH_EUFnaCMA_Adversary extends I_RSAFDH_EUF_Adversary<I_RSAFDH_EUFnaCMA_Challenger> {

}
