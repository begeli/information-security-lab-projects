package reductions;

import dcr.I_DCR_Adversary;
import paillier.I_Paillier_Adversary;
import paillier.I_Paillier_Challenger;
import basics.IReduction;
import dcr.I_DCR_Challenger;

/**
 * The interface for you solution. This interface adds an additional method
 * ({@code setAdversary}) which will be used by the TestRunner to provide you
 * with an adversary for the DDH assumption.
 */
public interface I_DCR_Paillier_Reduction
                extends IReduction<I_DCR_Challenger, Boolean>, I_DCR_Adversary, I_Paillier_Challenger {
        /**
         * The TestRunner will use this method to give you an adversary for the Paillier
         * Ind-CPA security game.
         * 
         * @param adversary the adversary which you need to use to solve the DCR
         *                  challenge. In this method, you should store the adversary.
         */
        void setAdversary(I_Paillier_Adversary adversary);
}
