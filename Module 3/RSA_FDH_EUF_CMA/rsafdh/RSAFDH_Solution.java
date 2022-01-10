package rsafdh;

import java.math.BigInteger;

/**
 * The solution which an RSA-FDH EUF adversary must return to its challenger in
 * the EUF security game of the RSA-FDH signing scheme.
 * 
 * A solution to the RSA-FDH EUF security game consists of a {@code message} and
 * a forged {@code signature}. The solution is valid iff {@code signature} can
 * be verified to be a signature of {@code message} under the given verification
 * key for RSA-FDH and if the adversary never asked the challenger for a
 * signature of message.
 * 
 * @author Julia
 */
public class RSAFDH_Solution {
    /**
     * The message which is to be signed.
     */
    public final String message;
    /**
     * The forged signature corresponding to the message.
     */
    public final BigInteger signature;

    /**
     * Creates a new RSA-FDH solution.
     * 
     * @param message   The message which is to be signed.
     * @param signature The forged signature corresponding to the message.
     */
    public RSAFDH_Solution(String message, BigInteger signature) {
        this.message = message;
        this.signature = signature;
    }
}