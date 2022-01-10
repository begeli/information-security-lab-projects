package rsafdh.eufnacma;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import rsafdh.RSAFDH_PK;
import rsafdh.I_RSAFDH_EUF_Challenger;

/**
 * An RSA-FDH EUF-naCMA challenger plays the EUF-naCMA security game of the
 * RSA-FDH signing scheme with implementations of the
 * {@code I_RSAFDH_EUFnaCMA_Adversary} interface.
 * 
 * Challengers of this kind offer two addtional methods:
 * {@code submitMessagesAndGetPK} and {@code getSignatures}. When run, an
 * EUF-naCMA adversary will use {@code submitMessagesAndGetPK} at the beginning
 * of the game to commit itself to a list of messages, for which it will ask
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
public interface I_RSAFDH_EUFnaCMA_Challenger extends I_RSAFDH_EUF_Challenger {
    /**
     * When you call the {@code run} method of an RSAFDH_EUFnaCMA_Adversary, it will
     * first call this method and submit a list of messages and challenge message
     * and expect a public key of the RSA-FDH scheme in return.
     * 
     * @param messages         A list of messages which you need to sign. The
     *                         signatures of this messages are returned in
     *                         {@code getSignatures()}.
     * @param challengeMessage The challenge message that the adversary will attempt
     *                         to forge a signature on. You may assume that
     *                         challengeMessage is not contained in messages.
     * @return a verification key for the RSA-FDH scheme for which the adversary is
     *         supposed to forge a signature.
     */
    public RSAFDH_PK submitMessagesAndGetPK(List<String> messages, String challengeMessage);

    /**
     * After calling {@code submitMessagesAndGetPK}, the adversary will call this
     * method and expect a list of signatures which match to messages which it
     * submitted in {@code submitMessagesAndGetPK}.
     * 
     * The signatures are expected to be returned as map such that for each message
     * m in messages the map has an entry (m, sig) such that sig is a valid
     * signature for m under the public key which you returned in
     * {@code submitMessagesAndGetPK}.
     * 
     * If there is a message m in messages for which there is no valid signature in
     * the return value of this method, then adversary cannot work correctly and
     * will only have negligible advantage in forging a signature.
     * 
     * @return a map which assigns to each message in messages a valid signature.
     */
    public Map<String, BigInteger> getSignatures();
}
