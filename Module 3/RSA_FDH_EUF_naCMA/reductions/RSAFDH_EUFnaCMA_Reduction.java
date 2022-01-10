package reductions;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import rsa.I_RSA_Challenger;
import rsa.RSA_Challenge;
import rsafdh.RSAFDH_PK;
import rsafdh.RSAFDH_Solution;
import rsafdh.eufnacma.I_RSAFDH_EUFnaCMA_Adversary;
import rsafdh.eufnacma.I_RSAFDH_EUFnaCMA_Challenger;

import schemes.RSA_Modulus;
/**
 * Use this method to generate random BigIntegers.
 */
import static utils.NumberUtils.getRandomBigInteger;

/**
 * This is the file you need to implement.
 * 
 * Implement the methods {@code run}, {@code hash()},
 * {@code submitMessagesAndGetPK()} and {@code getSignatures()} of this class.
 * Do not change the constructor of this class.
 * 
 */
public class RSAFDH_EUFnaCMA_Reduction
        extends A_RSAFDH_EUF_Reduction<I_RSAFDH_EUFnaCMA_Adversary, I_RSAFDH_EUFnaCMA_Challenger>
        implements I_RSAFDH_EUFnaCMA_Reduction {
    /**
     * use this if you need a source of randomness
     */
    private SecureRandom random = new SecureRandom();
    
    private BigInteger y;
    private BigInteger e;
    private RSA_Modulus modulus;
    private List<String> messages;
    private Map<String, BigInteger> hashes = new HashMap<>();
    private String challengeMessage;
    
    private Map<String, BigInteger> signatures = new HashMap<>();
    /**
     * Do NOT change or remove this constructor. When your reduction can not provide
     * a working standard constructor, the TestRunner will not be able to test your
     * code and you will get zero points.
     */
    public RSAFDH_EUFnaCMA_Reduction() {
        // Do not add any code here!
    }

    @Override
    public BigInteger run(I_RSA_Challenger challenger) {

        RSA_Challenge challenge = challenger.getChallenge();
        // at the end of this method you need to return a solution to challenge
    
        this.y = challenge.y;
        this.e = challenge.e;
        this.modulus = challenge.modulus;
        //this.hashes = new HashMap<>();
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
        // your code here
        if (hashes.containsKey(message)) {
          return hashes.get(message);
        }
        
        BigInteger hash = (this.signatures).get(message);
        hash = (hash).modPow(this.e, this.modulus.getN());
        hashes.put(message, hash);
        
        return hash;
    }

    @Override
    public RSAFDH_PK submitMessagesAndGetPK(List<String> messages, String challengeMessage) {
        // your code here
        this.messages = messages;
        
        for (String message : this.messages) {
          BigInteger signature = utils.NumberUtils.getRandomBigInteger(random, this.modulus.getN()); // TODO: Incomplete
          this.signatures.put(message, signature);
        }
        
        this.challengeMessage = challengeMessage;
        this.hashes.put(challengeMessage, this.y);
        
        RSAFDH_PK publicKey = new RSAFDH_PK(this.modulus, this.e);
        
        return publicKey;
    }

    @Override
    public Map<String, BigInteger> getSignatures() {
        // you need to return here the signatures to the messages you received in
        // submitMessagesAndGetPK
        
      
        // you can put elements in signatures by:
        // signatures.put(message, signature);

        // your code here

        return signatures;
    }

}