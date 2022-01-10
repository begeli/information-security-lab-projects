package reductions;

import ddh.DDH_Challenge;
import genericGroups.IRandomGroupElement;
import randomness.IRandomVariable;
import squaredh.I_SquareDH_Challenger;
import squaredh.SquareDH_Challenge;

/**
 * This is the file you need to implement.
 * 
 * Implement the methods {@code run} and {@code getChallenge()} of this class.
 * Do not change the constructor of this class.
 * 
 */
public class SquareDH_DDH_Reduction extends A_SquareDH_DDH_Reduction<IRandomGroupElement, IRandomVariable> {
    IRandomGroupElement gen;
    IRandomGroupElement x;
    IRandomGroupElement y;
    IRandomVariable random;
    
    /**
     * Do NOT change or remove this constructor. When your reduction can not provide
     * a working standard constructor, the TestRunner will not be able to test your
     * code and you will get zero points.
     */
    public SquareDH_DDH_Reduction() {
        // Do not add any code here!
    }

    @Override
    public Boolean run(I_SquareDH_Challenger<IRandomGroupElement, IRandomVariable> challenger) {
        // This is one of the both methods you need to implement.

        // By the following call you will receive a SqDH challenge.
        SquareDH_Challenge<IRandomGroupElement> challenge = challenger.getChallenge();
        // You need to decide if challenge is a real Square DH tuple and return true if
        // so.
        // (Return false if challenge is not a real SqDH tuple.)

        IRandomGroupElement generator = challenge.generator;
        IRandomGroupElement a = challenge.a;
        IRandomGroupElement b = challenge.b;

        // You can ask the SqDH challenger for ONE random variable which is distributed
        // independently of a and b.
        IRandomVariable R = challenger.getRandomVariable();

        /**
         * You should write some code here...
         */
         this.gen = generator;
         this.x = a;
         this.y = b;
         this.random = R;

        // The next line will start the DDH adversary which you are given.
        // Note that adversary will then call your getChallenge() method (you
        // should implement it accordingly).
        // If adversary gets a correct DDH challenge from you it will tell you, if the
        // ddh challenge you provided was real or not.
        // However, note that your DDH tuple must be of the correct form for your
        // adversary.
        boolean ddh_is_real = adversary.run(this);
        // Remember that you should implement a TIGHT reduction. So your code may call
        // adversary.run(this) at most once.

        boolean sqdh_is_real = false;

        /**
         * You should write some code here...
         */
        sqdh_is_real = ddh_is_real;

        return sqdh_is_real;
    }

    @Override
    public DDH_Challenge<IRandomGroupElement> getChallenge() {
        // This is the second method you need to implement.
        // You need to create a DDH challenge here which will be given to your DDH
        // adversary.
        IRandomGroupElement generator = this.gen;
        IRandomGroupElement x = this.x;
        IRandomGroupElement y = x.power(this.random); // x.multiply(generator.power(R))
        IRandomGroupElement z = (this.y).power(this.random); // z.R essentially and we are checking z.R == xy.R
        // Instead of null, your ddh challenge should consist of meaningful group
        // elements.
        DDH_Challenge<IRandomGroupElement> ddh_challenge = new DDH_Challenge<IRandomGroupElement>(generator, x, y, z);

        return ddh_challenge;
    }

}
