package rsa;

import java.math.BigInteger;

import basics.*;

/**
 * An RSA adversary decides RSA challenges. The challenges given to this
 * adversary should be of type RSA_Challenge.
 * <p>
 * An RSA adversary may assume that the challenges (N, y, e) it receives are
 * distributed appropiately. I.e. N is a real RSA modulus N = PQ for two random
 * big primes P and Q whose bitlength equals the security parameter, y is drawn
 * uniformly at random from Z/NZ and e is a random number which is coprime to
 * phi(N).
 * 
 * @author Nico
 */
public interface I_RSA_Adversary extends IAdversary<I_RSA_Challenger, BigInteger> {

}