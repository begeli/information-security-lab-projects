package reductions;

import rsafdh.eufcma.I_RSAFDH_EUFCMA_Adversary;
import rsafdh.eufcma.I_RSAFDH_EUFCMA_Challenger;

/**
 * Reduction from RSA to EUF CMA security of RSA FDH. The interface for your
 * solution.
 */
public interface I_RSAFDH_EUFCMA_Reduction
                extends I_RSAFDH_Reduction<I_RSAFDH_EUFCMA_Adversary>, I_RSAFDH_EUFCMA_Challenger {

}
