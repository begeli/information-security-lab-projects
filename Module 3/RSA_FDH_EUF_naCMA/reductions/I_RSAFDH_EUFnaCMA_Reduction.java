package reductions;

import rsafdh.eufnacma.I_RSAFDH_EUFnaCMA_Adversary;
import rsafdh.eufnacma.I_RSAFDH_EUFnaCMA_Challenger;

/**
 * Reduction from RSA to EUF naCMA security of RSA FDH. The interface for your
 * solution.
 */
public interface I_RSAFDH_EUFnaCMA_Reduction
                extends I_RSAFDH_Reduction<I_RSAFDH_EUFnaCMA_Adversary>, I_RSAFDH_EUFnaCMA_Challenger {

}