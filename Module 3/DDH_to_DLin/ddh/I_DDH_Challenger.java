package ddh;

import basics.IChallenger;

/**
 * A DDH challenger provides DDH challenges and plays the security game of the
 * DDH assumption with implementations of the {@code I_DDH_Adversary} interface.
 * It has a method {@code getChallenge()} which will be called by a DDH
 * adversary and which provides the DDH challenge in the corresponding security
 * game.
 * <p>
 * Additionally, when playing the DDH game with a reduction, a DDH challenger
 * offers the method {@code getRandomVariable} which the reduction can use to
 * get two fresh random variables. However, when this interface is implemented
 * by a reduction, then the reduction does not need to implement method
 * {@code getRandomVariable}.
 * 
 * @param G the type of group elements of the given challenge. Ideally, G equals
 *          IRandomGroupElement.
 * @param E the type of exponents of the group elements of type G. If G equals
 *          IRandomGroupElement, then E should be IRandomVariable (this means,
 *          random group elements can have random variables as exponents).
 */
public interface I_DDH_Challenger<G, E> extends IChallenger {
    /**
     * Returns the challenge of this challenger. This method should always return
     * the same challenge, no matter how often it has been called.
     * 
     * @return the challenge of this challenger.
     */
    DDH_Challenge<G> getChallenge();

    /**
     * When calling this method, the DDH challenger will return a new explicit
     * random variable. However, note that you can use this method at most twice!
     * <p>
     * When called for the first time, this method will return a new random variable
     * R1. The second time, this method will return a new random variable R2 which
     * is independent of R1. However each subsequent call will result in an
     * IllegalArgumentException.
     * 
     * @return The first call of this method returns a random variable R1. The
     *         second call of this method returns an independent random variable R2.
     *         Both random variables are independent of the exponents of the DDH
     *         challenge issued by this challenger.
     * 
     * @throws IllegalArgumentException will be thrown if this method is called for
     *                                  a third time.
     */
    E getRandomVariable() throws IllegalArgumentException;
}
