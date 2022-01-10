package basics;

/**
 * A generic interface for all adversaries for hierarchical clarity. All
 * specific adversaries (and reductions) must implement this interface.
 * <p>
 * Each adversary must implement a {@code run} method. This run method is the
 * starting point for the adversary.
 * 
 * @param C determines the type of challenger (and therefore, indirectly, the
 *          type of challenges this adversary will solve).
 * @param S determines the type of solutions this adversary returns. If this
 *          adversary is to solve decisional problems then S should be Boolean.
 *          If this adversary is to solve computational problems like, e.g. RSA,
 *          then this type should be more complex, e.g. BigInteger.
 * 
 * @author Nico
 */
public interface IAdversary<C extends IChallenger, S> {
    /**
     * When calling this method the adversary will start to "work". You need to
     * provide a {@code challenger} which the adversary will ask for a challenge and
     * additional information (depending on the security game the adversary plays
     * with the challenger). After the adversary is done with its computation this
     * will method will return a solution to the challenge which was proposed by the
     * challenger.
     * <p>
     * If you are a reduction and want to use a challenger, you need to give
     * yourself as challenger to the adversary when calling this method (and
     * implement your {@code getChallenge()} method appropiately).
     * <p>
     * <b>Important Note:</b> When you call this method as a reduction, you must
     * make sure that the distribution of the challenge and additional information
     * you give to the adversary is indistinguishable to the distribution of the
     * challenge and additional information the adversary would get from the
     * "normal" challenger. If the view you provide to the adversary can be
     * distinguished from the view it would have in the normal security game, the
     * adversary is not guaranteed anymore to work correctly and might only have
     * negligible advantage in solving your challenge.
     * <p>
     * <b>Another Important Note:</b> If you need to implement a TIGHT reduction you
     * must call the run method of your adversary at most once. If you call the run
     * method of your adversary twice or more, your reduction is not tight anymore
     * and will only receive partial points.
     * 
     * @param challenger the challenger from which this adversary will get this
     *                   challenge and additional information which is defined by
     *                   the security game which this adversary will play with the
     *                   given challenger. If you are a reduction, you should give
     *                   yourself as challenger.
     * @return the adversary will try to solve the challenge provided by the given
     *         challenger and return it in this method here. Most adversaries will
     *         -- with overhwelming probability -- return a correct solution.
     *         However, note that the view the adversary has while it plays the
     *         security game with {@code challenger} must be indistinguishable from
     *         the view it would have in its normal security game. If both views are
     *         not indistinguishable, then there are no guarantees for the success
     *         probability of this adversary anymore.
     */
    S run(C challenger);
}