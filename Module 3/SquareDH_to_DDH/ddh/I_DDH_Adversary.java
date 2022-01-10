package ddh;

import basics.IAdversary;

/**
 * A DDH adversary decides DDH challenges. The challenges given to this
 * adversary should be of type DDH_Challenge<G>.
 * <p>
 * Note that a ddh adversary only has a non-negligible advantage in deciding a
 * ddh challenge (g, g^x, g^y, g^z) if the exponents x, y, z are distributed
 * correctly. I.e., if (g, g^x, g^y, g^z) is a real ddh tuple, then x and y must
 * be drawn uniformly and independently at random. If (g, g^x, g^y, g^z) is not
 * a real ddh tuple, then x, y and z must be drawn uniformly and independently
 * at random.
 * <p>
 * If you are a SquareDH_DDH_Reduction using this DDH adversary, then remember
 * that your challenges must be of a special form. In particular, if (g, g^a,
 * g^b) is the Square DH challenge and R is the random variable you received by
 * your SqDH challenger, then the exponent x of the second group element you
 * give to this adversary must be a while the exponent y of the third group
 * element you give to this adversary must either be a * R or a + R.
 * 
 * If your reduction does not follow those rules, the adversary will not be able
 * to decide the ddh challenge you give it and it will return an arbitrary
 * boolean as answer.
 * <p>
 * Further, if you are a TIGHT reduction and use this adversary, note that you
 * should call the {@code run} method of this adversary at most once.
 * 
 * 
 * @param G the type of group elements of the given challenge. Ideally, G equals
 *          IRandomGroupElement.
 * @param E the type of exponents of the group elements of type G. If G equals
 *          IRandomGroupElement, then E should be IRandomVariable (this means,
 *          random group elements can have random variables as exponents).
 */
public interface I_DDH_Adversary<G, E> extends IAdversary<I_DDH_Challenger<G, E>, Boolean> {

}
