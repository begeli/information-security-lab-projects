package squaredh;

import basics.IAdversary;

/**
 * A SquareDH adversary decides SquareDH challenges. The challenges given to
 * this adversary should be of type SquareDH_Challenge<G>.
 * 
 * @param G the type of group elements of the given challenge. Ideally, G equals
 *          IRandomGroupElement.
 * @param E the type of exponents of the group elements of type G. If G equals
 *          IRandomGroupElement, then E should be IRandomVariable (this means,
 *          random group elements can have random variables as exponents).
 */
public interface I_SquareDH_Adversary<G, E> extends IAdversary<I_SquareDH_Challenger<G, E>, Boolean> {

}
