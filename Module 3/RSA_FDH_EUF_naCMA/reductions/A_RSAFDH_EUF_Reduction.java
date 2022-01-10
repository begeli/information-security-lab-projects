package reductions;

import rsafdh.I_RSAFDH_EUF_Adversary;
import rsafdh.I_RSAFDH_EUF_Challenger;

/**
 * For your convenience, this class implements the {@code setAdversary} method
 * for you and has a field ({@code adversary}) in which it will store the DLin
 * adversary you get by the TestRunner.
 * 
 * @param A determines the type of the adversary and the mode of EUF game (NMA,
 *          naCMA, CMA).
 * @param C determinest the type of the challenger and the mode of EUF game.
 **/
public abstract class A_RSAFDH_EUF_Reduction<A extends I_RSAFDH_EUF_Adversary<C>, C extends I_RSAFDH_EUF_Challenger>
        implements I_RSAFDH_Reduction<A> {

    /**
     * An RSA-FDH EUF adversary to help you with solving your challenge.
     * <p>
     * Remember that RSA-FDH EUF adversaries will always ask their challenger for
     * multiple hash queries for some messages (the number of hash queries this
     * adversary will ask is specified by {@code numHashQueries()}).
     * 
     * An EUF adversary will at the end of the game always come up with an RSAFDH
     * Solution. That is, it will come up with a message m and a forged signature
     * for this message m where it is guaranteed that this adversary has never seen
     * a signature for the message m before.
     * <p>
     * The type of the challenger and the mode of the adversary (CMA, NMA, naCMA) is
     * yet to be specified by the parameters A and C.
     * <p>
     * If you are a reduction using this adversary, then remember that you need to
     * play the corresponding security game correctly with this adversary.
     * Otherwise, this adversary may only have a negligible advantage in forging a
     * correct signature. Further, note that you may call the run method of your
     * adversaries at most once.
     */
    protected A adversary;

    @Override
    public void setAdversary(A adversary) {
        this.adversary = adversary;
    }
}
