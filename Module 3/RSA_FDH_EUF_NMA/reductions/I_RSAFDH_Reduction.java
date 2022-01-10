package reductions;

import java.math.BigInteger;

import basics.IReduction;
import rsafdh.I_RSAFDH_EUF_Challenger;
import rsa.*;

/**
 * Reduction from RSA to EUF security of RSA FDH
 * 
 * @param A determines which kind of RSAFDH adversary this reduction will use
 *          and which kind of security game this reduction has to play with its
 *          adversary.
 * 
 * @author Julia
 */
public interface I_RSAFDH_Reduction<A>
        extends IReduction<I_RSA_Challenger, BigInteger>, I_RSA_Adversary, I_RSAFDH_EUF_Challenger {
    /**
     * The TestRunner will use this method to give you an adversary for the EUFCMA /
     * EUFnaCMA / EUFNMA security game of the RSA FDH signature scheme (depending on
     * the type A).
     * 
     * @param adversary the adversary which you need to use to solve the RSA
     *                  challenge. In this method, you should store the adversary.
     */
    void setAdversary(A adversary);
}
