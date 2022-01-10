package paillier;

import basics.IAdversary;

/**
 * This interface captures the functionality of an adversary in the Ind
 * CPA-security game of the Paillier encryption scheme.
 * <p>
 * Adversaries which implement this interface will -- when their run() method is
 * called -- always ask their challenger for a public key of the Paillier
 * encryption scheme. After receiving a Paillier encryption scheme, the
 * adversary will ask the challenger for a challenge ciphertext by calling its
 * {@code getChallenge(BigInteger m_0, BigInteger m_1)} method. When receiving a
 * ciphertext c, the adversary tries to determine which message has been
 * encrypted in c. If c is an encryption of m_0 under the given public key, then
 * the adversary will always return 0 in its run() method. If c is an encryption
 * of m_1 under the given public key, then the adversary will always return 1 in
 * its run() method. In all other cases, there are no guarantees which number
 * the adversary will return.
 * <p>
 * If you are a TIGHT reduction using this adversary, then remember that you may
 * call the run method of this adversary at most once.
 * 
 * @author Nico
 */
public interface I_Paillier_Adversary extends IAdversary<I_Paillier_Challenger, Integer> {
}