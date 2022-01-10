package reductions;

import ddh.I_DDH_Adversary;
import genericGroups.IBasicGroupElement;

/**
 * For your convenience, this class implements the {@code setAdversary} method
 * for you and has a field ({@code adversary}) in which it will store the DDH
 * adversary you get by the TestRunner.
 * 
 * @author Julia
 **/
public abstract class A_SquareDH_DDH_Reduction<G extends IBasicGroupElement<G>, E>
        implements I_SquareDH_DDH_Reduction<G, E> {
    /**
     * A DDH adversary to help you with solving your challenge.
     * <p>
     * Note that a ddh adversary only has a non-negligible advantage in deciding a
     * ddh challenge (g, g^x, g^y, g^z) if the exponents x, y, z are distributed
     * correctly. I.e., if (g, g^x, g^y, g^z) is a real ddh tuple, then x and y must
     * be drawn uniformly and independently at random. If (g, g^x, g^y, g^z) is not
     * a real ddh tuple, then x, y and z must be drawn uniformly and independently
     * at random.
     * <p>
     * Remember that your challenges must be of a special form. In particular, if
     * (g, g^a, g^b) is the Square DH challenge and R is the random variable you
     * received by your SqDH challenger, then the exponent x of the second group
     * element you give to this adversary must be a while the exponent y of the
     * third group element you give to this adversary must either be a * R or a + R.
     * 
     * If your reduction does not follow those rules, the adversary will not be able
     * to decide the ddh challenge you give it and it will return an arbitrary
     * boolean as answer.
     * <p>
     * Further, since you are a TIGHT reduction, note that you should call the
     * {@code run} method of this adversary at most once.
     */
    protected I_DDH_Adversary<G, E> adversary;

    @Override
    public void setAdversary(I_DDH_Adversary<G, E> adversary) {
        this.adversary = adversary;
    }
}
