package genericGroups;

import randomness.IRandomVariable;

/**
 * This interface specifies the IBasicGroupElement interface. It adds a new
 * method which allows to compute the X-th power of a group element where X is a
 * random variable over the cyclic ring Z/qZ.
 * 
 * @author Akin
 */
public interface IRandomGroupElement extends IBasicGroupElement<IRandomGroupElement> {
    /**
     * Returns a new group element which encodes the product of the given argument
     * and the exponent of this group element. Calling this method will neither
     * change this object nor the the given argument!
     * 
     * @param exponent A number which shall be multiplied with the number encoded by
     *                 this group element.
     * @return the k-th power of this group element, where k is the given exponent.
     * @throws IllegalArgumentException will be thrown if this element has been
     *                                  illegally tampered.
     * @throws NullPointerException     will be thrown if the given argument is
     *                                  null.
     */
    IRandomGroupElement power(IRandomVariable exponent) throws IllegalArgumentException, NullPointerException;
}
