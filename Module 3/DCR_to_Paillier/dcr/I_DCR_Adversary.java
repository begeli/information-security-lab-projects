package dcr;

import basics.*;

/**
 * A DCR adversary decides DCR challenges. The challenges given to this
 * adversary should be of type DCR_Challenge.
 * <p>
 * A DCR adversary may assume that the challenges (N, z) it receives are
 * distributed appropiately. I.e. N is a real RSA modulus N = PQ for two random
 * big primes P and Q whose bitlength equals the security parameter and z is
 * either drawn uniformly at random from Z/N^2 Z or an N-th power in Z/N^2 Z.
 * 
 * @author Nico
 */
public interface I_DCR_Adversary extends IAdversary<I_DCR_Challenger, Boolean> {

}