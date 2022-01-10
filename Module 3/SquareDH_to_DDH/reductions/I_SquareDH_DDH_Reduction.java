package reductions;

import basics.IReduction;
import ddh.I_DDH_Adversary;
import ddh.I_DDH_Challenger;
import genericGroups.IBasicGroupElement;
import squaredh.I_SquareDH_Adversary;
import squaredh.I_SquareDH_Challenger;

/**
 * The interface for you solution. This interface adds an additional method
 * ({@code setAdversary}) which will be used by the TestRunner to provide you
 * with an adversary for the DDH assumption.
 * 
 * Further, this interface gives a default implementation for the method
 * {@code getRandomVariable} (you don't need this method and should ignore it).
 * 
 * @param G the type of group elements of the given challenge. Ideally, G equals
 *          IRandomGroupElement.
 * @param E the type of exponents of the group elements of type G. If G equals
 *          IRandomGroupElement, then E should be IRandomVariable (this means,
 *          random group elements can have random variables as exponents).
 */
public interface I_SquareDH_DDH_Reduction<G extends IBasicGroupElement<G>, E> extends
                IReduction<I_SquareDH_Challenger<G, E>, Boolean>, I_DDH_Challenger<G, E>, I_SquareDH_Adversary<G, E> {
        /**
         * The TestRunner will use this method to give you an adversary for solving DDH
         * challenges.
         * 
         * @param adversary The adversary which you need to use to solve the SquareDH
         *                  challenge. In this method, you should store the adversary.
         */
        void setAdversary(I_DDH_Adversary<G, E> adversary);

        /**
         * This method is not needed in this case. Do not implement it!
         */
        default E getRandomVariable() {
                return null;
        }
}
