package rsa;

import basics.IChallenger;
import java.math.BigInteger;

/**
 * An RSA challenger provides RSA challenges and plays the security game of the
 * RSA assumption with implementations of the {@code I_RSA_Adversary} interface.
 * It has a method {@code getChallenge()} which will be called by an RSA
 * adversary and which provides the RSA challenge in the corresponding security
 * game.
 * 
 * @author Nico
 */
public interface I_RSA_Challenger extends IChallenger {
    /**
     * Returns the challenge of this challenger. This method should always return
     * the same challenge, no matter how often it has been called.
     * 
     * @return the challenge of this challenger.
     */
    RSA_Challenge getChallenge();

    /**
     * This method verifies that s is indeed the solution to the RSA challenge which
     * is returned by getChallenge(). I.e., if the RSA challenge of getChallenge()
     * is of the form (N, y, e), then this method returns true iff s^e mod N = y.
     * 
     * @param s the proposed solution.
     * @return true iff s is an e-th root of y modulo N.
     */
    boolean testSolution(BigInteger s);
}