package reductions;

import java.math.BigInteger;
import java.security.SecureRandom;

import dcr.DCR_Challenge;
import schemes.RSA_Modulus;
import dcr.I_DCR_Challenger;

import java.util.Random;
import java.math.BigInteger;
/**
 * This is the file you need to implement.
 * 
 * Implement the methods {@code run}, {@code getPaillierPK()} and
 * {@code getChallenge()} of this class. Do not change the constructor of this
 * class.
 * 
 */
public class DCR_Paillier_Reduction extends A_DCR_Paillier_Reduction {
    BigInteger z;
    RSA_Modulus modulus;
    int chosen_message;
    
    /**
     * use this if you need a source of randomness
     */
    private SecureRandom random = new SecureRandom();

    /**
     * Do NOT change or remove this constructor. When your reduction can not provide
     * a working standard constructor, the TestRunner will not be able to test your
     * code and you will get zero points.
     */
    public DCR_Paillier_Reduction() {
        // Do not add any code here!
    }

    @Override
    public Boolean run(I_DCR_Challenger challenger) {
        // This is one of the methods you need to implement.

        DCR_Challenge challenge = challenger.getChallenge();

        // your code goes here
        this.z = challenge.z;
        this.modulus = challenge.modulus;
        
        int chosen_message = adversary.run(this);

        // more code here
        boolean is_exponential = this.chosen_message == chosen_message;

        return is_exponential;
    }

    @Override
    public BigInteger getChallenge(final BigInteger m_0, final BigInteger m_1) {
        // you need to return a ciphertext here
        Random rand = new Random();
        
        this.chosen_message = random.nextInt(2);
        BigInteger msg = this.chosen_message == 0 ? m_0 : m_1;
        BigInteger ctxt = (this.modulus.getN()).add(BigInteger.ONE);
        ctxt = ctxt.modPow(msg, this.modulus.getN().pow(2));
        ctxt = (this.z).multiply(ctxt);
        
        return ctxt;
    }

    @Override
    public RSA_Modulus getPaillierPK() {
        // you need to return public key for the Paillier encryption scheme here
        return this.modulus;
    }
}
