package dlin;

import basics.IChallenger;

/**
 * A DLin challenger provides DLin challenges and plays the security game of the
 * DLin assumption with implementations of the {@code I_DLin_Adversary}
 * interface. It has a method {@code getChallenge()} which will be called by a
 * DLin adversary and which provides the DLin challenge in the corresponding
 * security game.
 * 
 * @param G the type of group elements of the given challenge. Ideally, G equals
 *          IRandomGroupElement.
 * @param E the type of exponents of the group elements of type G. If G equals
 *          IRandomGroupElement, then E should be IRandomVariable (this means,
 *          random group elements can have random variables as exponents).
 * 
 * @author Julia
 */
public interface I_DLin_Challenger<G> extends IChallenger {
    /**
     * Returns the challenge of this challenger. This method should always return
     * the same challenge, no matter how often it has been called.
     * 
     * @return the challenge of this challenger.
     */
    public DLin_Challenge<G> getChallenge();
}
