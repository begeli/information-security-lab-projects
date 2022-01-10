package reductions;

import paillier.I_Paillier_Adversary;

/**
 * For your convenience, this class implements the {@code setAdversary} method
 * for you and has a field ({@code adversary}) in which it will store the DLin
 * adversary you get by the TestRunner.
 */
public abstract class A_DCR_Paillier_Reduction implements I_DCR_Paillier_Reduction {

    /**
     * A Paillier adversary to help you with solving your challenge.
     * <p>
     * Note, if you are a TIGHT reduction and use this adversary, note that you
     * should call the {@code run} method of this adversary at most once.
     */
    protected I_Paillier_Adversary adversary;

    @Override
    public void setAdversary(I_Paillier_Adversary adversary) {
        this.adversary = adversary;
    }
}
