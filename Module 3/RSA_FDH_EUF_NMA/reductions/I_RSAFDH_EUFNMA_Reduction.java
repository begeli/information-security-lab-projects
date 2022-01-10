package reductions;

import rsafdh.eufnma.I_RSAFDH_EUFNMA_Adversary;
import rsafdh.eufnma.I_RSAFDH_EUFNMA_Challenger;

/**
 * Reduction from RSA to EUF NMA security of RSA FDH. The interface for your
 * solution.
 * 
 * @author Julia
 */
public interface I_RSAFDH_EUFNMA_Reduction
        extends I_RSAFDH_Reduction<I_RSAFDH_EUFNMA_Adversary>, I_RSAFDH_EUFNMA_Challenger {

}
