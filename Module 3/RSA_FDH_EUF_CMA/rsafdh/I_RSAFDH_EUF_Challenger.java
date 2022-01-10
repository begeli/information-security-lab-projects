package rsafdh;

import java.math.BigInteger;

import basics.IChallenger;

/**
 * An RSAFDH EUF challenger plays the EUF security game of the RSA-FDH signing
 * scheme with implementations of the {@code I_RSAFDH_EUF_Adversary} interface.
 * <p>
 * Derivatives of this interface determine how capable the adversary will be in
 * the corresponding security games. In each case, the RSAFDH EUF adversary will
 * be able to ask the challenger for hash values of messages. Therefore, this
 * interface offers a method {@code hash(message)} which will return a
 * BigInteger for a given String.
 * <p>
 * When you implement this interface as a reduction, you must make sure that the
 * hash functionality, which you implement, is COLLISION-RESISTANT. I.e., when
 * asking hash values h(m1), h(m2) for two different messages m1 and m2, the
 * hash values h(m1) and h(m2) should differ in an overwhelming number of cases.
 * 
 * Further, you must make sure that your hash oracle is CONSISTENT. I.e., when
 * calling the method {@code hash} multiple times for a message m, it should
 * always return the same hash value for this message.
 * 
 * @author Julia
 */
public interface I_RSAFDH_EUF_Challenger extends IChallenger {
    /**
     * The hash function to full-domain-hash messages with. Given any non-null
     * string, this method must return a number in {0, ..., N-1} (where is the
     * modulus of the RSAFDH scheme).
     * 
     * This hash functionality must be COLLISION-RESISTANT. I.e., if m1 and m2 are
     * two different, non-null Strings, then hash(m1).equals(hash(m2)) may hold only
     * in a negligible number of cases.
     * 
     * Further, this functionality must be CONSISTENT. For a non-null String m,
     * hash(m) must always return the same number in one run of the RSA-FDH EUF
     * security game.
     * 
     * @param message the message to be hashed. A non-null string.
     * @return a number in {0, ..., N-1}. The class which implements this
     *         functionality may return an arbitrary number here, but must make sure
     *         that its hash-functionality is COLLISION-RESISTANT and CONSISTENT.
     */
    BigInteger hash(String message);
}