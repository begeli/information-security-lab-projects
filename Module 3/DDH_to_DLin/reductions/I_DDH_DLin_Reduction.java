package reductions;

import basics.IReduction;
import ddh.I_DDH_Adversary;
import ddh.I_DDH_Challenger;
import dlin.I_DLin_Adversary;
import dlin.I_DLin_Challenger;
import genericGroups.IBasicGroupElement;

/**
 * The interface for you solution. This interface adds an additional method
 * ({@code setAdversary}) which will be used by the TestRunner to provide you
 * with an adversary for the DDH assumption.
 * 
 * @param G the type of group elements of the given challenge. Ideally, G equals
 *          IRandomGroupElement.
 * @param E the type of exponents of the group elements of type G. If G equals
 *          IRandomGroupElement, then E should be IRandomVariable (this means,
 *          random group elements can have random variables as exponents).
 */
public interface I_DDH_DLin_Reduction<G extends IBasicGroupElement<G>, E> extends
        IReduction<I_DDH_Challenger<G, E>, Boolean>, I_DDH_Adversary<G, E>, I_DLin_Challenger<G> {

    /**
     * The TestRunner will use this method to give you an adversary for solving DLin challenges.
     * 
     * @param adversary the adversary which you need to use to solve the DDH
     *                  challenge. In this method, you should store the adversary.
     */
    void setAdversary(I_DLin_Adversary<G, E> adversary);
}
