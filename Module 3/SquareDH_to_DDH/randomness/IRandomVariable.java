package randomness;

import java.math.BigInteger;

/**
 * Objects which implement this interface represent random variables over Z/qZ.
 * They are immutable and can be multiplied and added with over random variables
 * or numbers of Z/qZ (for a big prime q).
 * 
 * @author Akin
 */
public interface IRandomVariable {
    /**
     * Returns a new random variable which is equal to the sum of this random
     * variable and the given argument. Calling this method will neither change this
     * object nor the the given argument!
     * 
     * @param otherElement A random variable which shall be added to this random
     *                     variable.
     * @return the sum of this random variable and the given random variable.
     * @throws IllegalArgumentException will be thrown if otherElement has been
     *                                  tampered with.
     * @throws NullPointerException     will be thrown if otherElement is null.
     */
    IRandomVariable add(IRandomVariable otherElement) throws IllegalArgumentException, NullPointerException;

    /**
     * Returns a new random variable which equals this random variable plus the
     * given number. Calling this method will neither change this object nor the the
     * given argument!
     * 
     * @param number the element of Z/qZ which shall be added to this random
     *               variable.
     * @return the sum of this random variable and the given number.
     * @throws NullPointerException will be thrown if number is null.
     */
    IRandomVariable add(BigInteger number) throws NullPointerException;

    /**
     * Returns a new random variable which is equal to the product of this random
     * variable and the given argument. Calling this method will neither change this
     * object nor the the given argument!
     * 
     * @param otherElement A random variable which shall be multiplied to this
     *                     random variable.
     * @return the product of this random variable and the given random variable.
     * @throws IllegalArgumentException will be thrown if otherElement has been
     *                                  tampered with.
     * @throws NullPointerException     will be thrown if otherElement is null.
     */
    IRandomVariable multiply(IRandomVariable otherElement) throws IllegalArgumentException, NullPointerException;

    /**
     * Returns a new random variable which equals this random variable multiplied
     * with the given number. Calling this method will neither change this object
     * nor the the given argument!
     * 
     * @param number the element of Z/qZ which shall be multiplied with this random
     *               variable.
     * @return the product of this random variable and the given number.
     * @throws NullPointerException will be thrown if number is null.
     */
    IRandomVariable multiply(BigInteger number) throws NullPointerException;

    /**
     * Returns iff this random variable will always be zero.
     * 
     * @return true iff the event, that this random variable will be zero, is 100%.
     */
    boolean isZero();

    /**
     * Returns iff this random variable will always be the same value over Z/qZ.
     * 
     * @return true iff there is a c \in Z/qZ s.t. Probability[ this = c ] = 100%.
     */
    boolean isConstant();

    /**
     * Returns a new random variable which is equal to the this random variable
     * minus the given argument. Calling this method will neither change this object
     * nor the the given argument!
     * 
     * @param otherElement A random variable which shall be subtracted from this
     *                     random variable.
     * @return the difference of this random variable and the given random variable.
     * @throws IllegalArgumentException will be thrown if otherElement has been
     *                                  tampered with.
     * @throws NullPointerException     will be thrown if otherElement is null.
     */
    default IRandomVariable subtract(IRandomVariable otherElement)
            throws IllegalArgumentException, NullPointerException {
        return this.add(otherElement.multiply(BigInteger.ONE.negate()));
    }

    /**
     * Returns a new random variable which equals this random variable minus the
     * given number. Calling this method will neither change this object nor the the
     * given argument!
     * 
     * @param number the element of Z/qZ which shall be subtracted from this random
     *               variable.
     * @return the difference of this random variable and the given number.
     * @throws NullPointerException will be thrown if number is null.
     */
    default IRandomVariable subtract(BigInteger number) throws NullPointerException {
        return this.add(number.negate());
    }

    /**
     * Flips the sign of this random variable. I.e., this method returns (-this).
     * Calling this method will not change this object!
     * 
     * @return a random variable which equals this random variable times -1.
     */
    default IRandomVariable negate() {
        return this.multiply(BigInteger.ONE.negate());
    }
}
