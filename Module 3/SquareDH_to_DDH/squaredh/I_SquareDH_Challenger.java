package squaredh;

import basics.IChallenger;

/**
 * A SquareDH challenger provides SquareDH challenges and plays the security
 * game of the SquareDH assumption with implementations of the
 * {@code I_SquareDH_Adversary} interface. It has a method
 * {@code getChallenge()} which will be called by a SquareDH adversary and which
 * provides the SquareDH challenge in the corresponding security game.
 * <p>
 * Additionally, when playing the SquareDH game with a reduction, a SquareDH
 * challenger offers the method {@code getRandomVariable} which the reduction
 * can use to get one fresh random variable. However, when this interface is
 * implemented by a reduction, then the reduction does not need to implement
 * method {@code getRandomVariable}.
 * 
 * @param G the type of group elements of the given challenge. Ideally, G equals
 *          IRandomGroupElement.
 * @param E the type of exponents of the group elements of type G. If G equals
 *          IRandomGroupElement, then E should be IRandomVariable (this means,
 *          random group elements can have random variables as exponents).
 */
public interface I_SquareDH_Challenger<G, E> extends IChallenger {
    /**
     * Returns the challenge of this challenger. This method should always return
     * the same challenge, no matter how often it has been called.
     * 
     * @return the challenge of this challenger.
     */
    SquareDH_Challenge<G> getChallenge();

    /**
     * When calling this method, the SquareDH challenger will return a new explicit
     * random variable. However, note that you can use this method at most once!
     * <p>
     * When called for the first time, this method will return a new random variable
     * R. Each subsequent call will result in an IllegalArgumentException.
     * 
     * @return The first call of this method returns a random variable R. This
     *         random variable is drawn uniformly at random and is independent of
     *         the exponents of the SquareDH challenge issued by this challenger.
     * 
     * @throws IllegalArgumentException will be thrown if this method is called for
     *                                  a second time.
     */
    E getRandomVariable();
}
