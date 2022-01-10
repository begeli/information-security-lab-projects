package reductions;

import ddh.DDH_Challenge;
import ddh.I_DDH_Challenger;
import dlin.DLin_Challenge;
import genericGroups.IRandomGroupElement;
import randomness.IRandomVariable;

/**
 * This is the file you need to implement.
 * 
 * Implement the methods {@code run} and {@code getChallenge()} of this class.
 * Do not change the constructor of this class.
 * 
 */
public class DDH_DLin_Reduction extends A_DDH_DLin_Reduction<IRandomGroupElement, IRandomVariable> {
    IRandomGroupElement gen;
    IRandomGroupElement x;
    IRandomGroupElement y;
    IRandomGroupElement z;
    IRandomVariable random1;
    IRandomVariable random2;
    
    /**
     * Do NOT change or remove this constructor. When your reduction can not provide
     * a working standard constructor, the TestRunner will not be able to test your
     * code and you will get zero points.
     */
    public DDH_DLin_Reduction() {
        // Do not add any code here!
    }

    @Override
    public Boolean run(I_DDH_Challenger<IRandomGroupElement, IRandomVariable> challenger) {
        // This is one of the both methods you need to implement.

        // By the following call you will receive a DDH challenge.
        DDH_Challenge<IRandomGroupElement> challenge = challenger.getChallenge();
        // You need to decide if challenge is a real DDH tuple and return true if
        // so.
        // (Return false if challenge is not a real DDH tuple.)

        IRandomGroupElement generator = challenge.generator;
        IRandomGroupElement x = challenge.x;
        IRandomGroupElement y = challenge.y;
        IRandomGroupElement z = challenge.z;

        // You can ask the SqDH challenger for TWO random variable which are distributed
        // independently of x, y and z.
        IRandomVariable R1 = challenger.getRandomVariable();
        IRandomVariable R2 = challenger.getRandomVariable();

        /**
         * You should write some code here...
         */
        this.gen = generator;
        this.x = x;
        this.y = y;
        this.z = z;
        this.random1 = R1;
        this.random2 = R2;

        // The next line will start the DLin adversary which you are given.
        // Note that adversary will then call your getChallenge() method (you
        // should implement it accordingly).
        // If adversary gets a correct DLin challenge from you it will tell you, if the
        // DLin challenge you provided was real or not.
        // However, note that your Dlin tuple must be of the correct form for your
        // adversary.
        boolean dlin_is_real = adversary.run(this);
        // Remember that you should implement a TIGHT reduction. So your code may call
        // adversary.run(this) at most once.

        boolean ddh_is_real = false;

        /**
         * You should write some code here...
         */
         ddh_is_real = dlin_is_real;

        return ddh_is_real;
    }

    @Override
    public DLin_Challenge<IRandomGroupElement> getChallenge() {
        // This is the second method you need to implement.
        // You need to create a DLin challenge here which will be given to your DLin
        // adversary.
        IRandomGroupElement generator = this.gen;
        IRandomGroupElement a = this.x;
        IRandomGroupElement b = generator.power(this.random1);
        IRandomGroupElement aTimesU = this.z;
        IRandomGroupElement bTimesV = b.power(this.random2);
        IRandomGroupElement w = (this.y).multiply(generator.power(this.random2));
        // Instead of null, your DLin challenge should consist of meaningful group
        // elements.
        DLin_Challenge<IRandomGroupElement> dlin_challenge = new DLin_Challenge<IRandomGroupElement>(generator, a, b,
                aTimesU, bTimesV, w);

        return dlin_challenge;
    }
}
