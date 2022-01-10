package reductions;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import rsa.I_RSA_Challenger;
import rsa.RSA_Challenge;
import rsafdh.RSAFDH_PK;
import rsafdh.RSAFDH_Solution;
import rsafdh.eufnma.I_RSAFDH_EUFNMA_Adversary;
import rsafdh.eufnma.I_RSAFDH_EUFNMA_Challenger;

import schemes.RSA_Modulus;
import utils.NumberUtils;
/**
 * Use this method to generate random BigIntegers.
 */
import static utils.NumberUtils.getRandomBigInteger;

/**
 * This is the file you need to implement.
 * 
 * Implement the methods {@code run}, {@code getPK()} and {@code hash()} of this
 * class. Do not change the constructor of this class.
 * 
 */
public class RSAFDH_EUFNMA_Reduction
        extends A_RSAFDH_EUF_Reduction<I_RSAFDH_EUFNMA_Adversary, I_RSAFDH_EUFNMA_Challenger>
        implements I_RSAFDH_EUFNMA_Reduction {
    /**
     * use this if you need a source of randomness
     */
    private SecureRandom random = new SecureRandom();
    
    private BigInteger y;
    private BigInteger e;
    private RSA_Modulus modulus;
    private Map<String, BigInteger> messageHashMappings = new HashMap<>();
    /**
     * Do NOT change or remove this constructor. When your reduction can not provide
     * a working standard constructor, the TestRunner will not be able to test your
     * code and you will get zero points.
     */
    public RSAFDH_EUFNMA_Reduction() {
        // Do not add any code here!
    }

    @Override
    public BigInteger run(I_RSA_Challenger challenger) {

        RSA_Challenge challenge = challenger.getChallenge();
        // at the end of this method you need to return a solution to challenge
        
        // your code goes here
        this.y = challenge.y;
        this.e = challenge.e;
        this.modulus = challenge.modulus;
        //messageHashMappings = new HashMap<>();
        
        // result is null which should not be the case
        RSAFDH_Solution result = adversary.run(this);
        
        // more code here
        if (result == null) {
          return BigInteger.ZERO;
        } 
        
        /*BigInteger msgHash = messageHashMappings.get(result.message);
        msgHash = msgHash.modPow(this.e, this.modulus.getN());
        BigInteger x = result.signature.multiply(msgHash);*/
        BigInteger x = result.signature;
        
        return x;
    }

    @Override
    public RSAFDH_PK getPk() {
        RSAFDH_PK publicKey = new RSAFDH_PK(this.modulus, this.e);
        
        return publicKey;
    }

    @Override
    public BigInteger hash(String message) {
        /*if (messageHashMappings.containsKey(message)) {
          return (this.y).multiply(messageHashMappings.get(message));
        }
        
        BigInteger hash = NumberUtils.getRandomBigInteger(this.random, this.modulus.getN());
        messageHashMappings.put(message, hash);
        return (this.y).multiply(hash);*/
        return this.y;
    }
}
