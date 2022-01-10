package reductions;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import rsa.I_RSA_Challenger;
import rsa.RSA_Challenge;
import rsafdh.RSAFDH_PK;
import rsafdh.RSAFDH_Solution;
import rsafdh.eufcma.I_RSAFDH_EUFCMA_Adversary;
import rsafdh.eufcma.I_RSAFDH_EUFCMA_Challenger;

/**
 * Use this method to generate random BigIntegers.
 */
import static utils.NumberUtils.getRandomBigInteger;
import schemes.RSA_Modulus;

/**
 * This is the file you need to implement.
 * 
 * Implement the methods {@code run}, {@code hash()}, {@code sign()} and
 * {@code getPK()} of this class. Do not change the constructor of this class.
 * 
 */
public class RSAFDH_EUFCMA_Reduction
        extends A_RSAFDH_EUF_Reduction<I_RSAFDH_EUFCMA_Adversary, I_RSAFDH_EUFCMA_Challenger>
        implements I_RSAFDH_EUFCMA_Reduction {
    /**
     * use this if you need a source of randomness
     */
    private SecureRandom random = new SecureRandom();
    
    private RSA_Modulus modulus;
    private BigInteger y;
    private BigInteger e;
    private Map<String, BigInteger> hashes = new HashMap<>();
    private Map<String, BigInteger> signatures = new HashMap<>();
    private int maxHashCall;
    private int hashCalls;
    /**
     * Do NOT change or remove this constructor. When your reduction can not provide
     * a working standard constructor, the TestRunner will not be able to test your
     * code and you will get zero points.
     */
    public RSAFDH_EUFCMA_Reduction() {
        // Do not add any code here!
    }

    @Override
    public BigInteger run(I_RSA_Challenger challenger) {
        RSA_Challenge challenge = challenger.getChallenge();
        //at the end of this method you need to return a solution to challenge
        this.modulus = challenge.modulus;
        this.y = challenge.y;
        this.e = challenge.e;
        this.maxHashCall = adversary.numHashQueries();
        this.hashCalls = 0;
        
        // your code goes here
        RSAFDH_Solution result = adversary.run(this);
        // more code here
        if (result == null) {
          return BigInteger.ZERO;
        }
        BigInteger x = result.signature;
        
        return x;
    }

    @Override
    public BigInteger hash(String message) {
        if (this.hashes.containsKey(message)) {
          return this.hashes.get(message);
        }
        
        this.hashCalls++;
        if (this.hashCalls == this.maxHashCall) {
          this.hashes.put(message, this.y);
          return this.y;
        } else if (signatures.containsKey(message)) {
          BigInteger hash = signatures.get(message).modPow(this.e, this.modulus.getN());
          hashes.put(message, hash);
          return hash;
        } else {
          BigInteger signature = utils.NumberUtils.getRandomBigInteger(random, this.modulus.getN());
          BigInteger hash = signature.modPow(this.e, this.modulus.getN());
          
          this.signatures.put(message, signature);
          this.hashes.put(message, hash);
          
          return hash;
        }
        /*if (this.hashes.containsKey(message)) {
          return this.hashes.get(message);
        }
        
        this.hashCalls++;
        if (this.hashCalls == this.maxHashCall) {
          return this.y;
        } else {
          BigInteger signature = utils.NumberUtils.getRandomBigInteger(random, this.modulus.getN());
          BigInteger hash = signature.modPow(this.e, this.modulus.getN());
          
          this.signatures.put(message, signature);
          this.hashes.put(message, hash);
          
          return hash;
        } */
    }

    @Override
    public RSAFDH_PK getPk() {
        RSAFDH_PK publicKey = new RSAFDH_PK(this.modulus, this.e);
        
        return publicKey;
    }

    @Override
    public BigInteger sign(String message) {
        if (this.signatures.containsKey(message)) {
          return this.signatures.get(message);
        }
        
        BigInteger signature = utils.NumberUtils.getRandomBigInteger(random, this.modulus.getN());
        this.signatures.put(message, signature);
        return signature;
        /*if (this.signatures.containsKey(message)) {
          return this.signatures.get(message);
        }
        
        BigInteger signature = utils.NumberUtils.getRandomBigInteger(random, this.modulus.getN());
        BigInteger hash = signature.modPow(this.e, this.modulus.getN());
        
        this.signatures.put(message, signature);
        this.hashes.put(message, hash);
        // your code here
        return signature;*/
    }
}