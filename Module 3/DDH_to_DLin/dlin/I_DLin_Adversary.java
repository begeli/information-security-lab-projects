package dlin;

import basics.IAdversary;

/**
 * A DLin adversary decides DLin challenges. The challenges given to this
 * adversary should be of type DLin_Challenge<G>.
 * <p>
 * Note that a DLin adversary only has a non-negligible advantage in deciding a
 * DLin challenge (g, g^a, g^b, g^(a * u), g^(b * v), g^w) if the exponents a,
 * b, u, v and w are distributed correctly. I.e., if (g, g^a, g^b, g^(a * u),
 * g^(b * v), g^w) is a real DLin tuple, then a, b, u and v must be distributed
 * uniformly and independently at random. If (g, g^a, g^b, g^(a * u), g^(b * v),
 * g^w) is not a real DLin tuple, then a, b, u, v and w must be drawn uniformly
 * and independently at random.
 * <p>
 * If you are a DDH_DLin_Reduction using this DLin adversary, then remember that
 * your challenges must be of a special form. In particular, if (g, g^x, g^y,
 * g^z) is the DDH challenge and R1, R2 are the random variables you received by
 * your DDH challenger, then the exponent a of the second group element you give
 * to this adversary must be x or y while the exponent b of the third group
 * element you give to this adversary must either be R1 or R2. Further, the
 * exponents of the other group elements of your DLin tuple must be chosen as
 * <b>simple</b> as possible while guaranteeing at the same time that (g, g^a,
 * g^b, g^(a * u), g^(b * v), g^w) is distributed like a real DLin tuple iff (g,
 * g^x, g^y, g^z) is distributed like a real DDH tuple; and that (g, g^a, g^b,
 * g^(a * u), g^(b * v), g^w) is distributed like a random DLin tuple iff (g,
 * g^x, g^y, g^z) is distributed like a random DDH tuple.
 * 
 * If your reduction does not follow those rules, the adversary will not be able
 * to decide the DLin challenge you give it and it will return an arbitrary
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
 * 
 * @author Julia
 */
public interface I_DLin_Adversary<G, E> extends IAdversary<I_DLin_Challenger<G>, Boolean> {

}
