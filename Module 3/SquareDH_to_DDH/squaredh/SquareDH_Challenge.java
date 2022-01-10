package squaredh;

/**
 * This class is a container object for a Decisional Square Diffie-Hellman
 * challenge tuple.
 * <p>
 * A SqDH tuple consists of three group elements: a generator g, a second
 * element g^a and a third group element g^b. A DDH tuple represents the problem
 * of deciding whether the exponent of the third group element is the square of
 * the exponent of the first element.
 * <p>
 * I.e., a DDH tuple represents the problem of deciding whether b equals a^2 or
 * if b was sampled uniformly and independently of a at random. When given a DDH
 * challenge (g, g^a, g^b) from a SqDH challenger there is a 50% probability,
 * that (g, g^a, g^b) is a <b>real</b> SqDH tuple, i.e., a was drawn uniformly
 * at random and b = a^2, and a 50% probability, that (g, g^a, g^b) is a
 * <b>random</b> tuple, i.e., a and b were drawn uniformly and independently at
 * random.
 * <p>
 * A correct solution for this SqDH tuple is a boolean value which is true iff
 * this tuple is real, i.e., iff b = a^2.
 * 
 * @param G this type determines the type of group elements of this challenge.
 *          Ideally, G should equal IRandomGroupElement.
 */
public class SquareDH_Challenge<G> {
    /**
     * A generator of the group. Usually an encoding of one.
     */
    public final G generator;
    /**
     * A group element of the form g^a, where g is the generator in this tuple.
     * Usually, g^a was drawn uniformly random from the group.
     */
    public final G a;
    /**
     * A group element of the form g^b, where g is the generator in this tuple. This
     * tuple is a real SqDH tuple iff b = a * a. If this tuple is not real, then g^b
     * was drawn uniformly from the group and independently of g^a.
     */
    public final G b;

    /**
     * Creates a new SqDH challenge.
     * 
     * @param generator A generator of the group. Usually an encoding of one.
     * @param a         A group element of the form g^a, where g is the generator in
     *                  this tuple. Usually, g^a was drawn uniformly random from the
     *                  group.
     * @param b         A group element of the form g^b, where g is the generator in
     *                  this tuple. This tuple is a real SqDH tuple iff b = a * a.
     *                  If this tuple is not real, then g^b was drawn uniformly from
     *                  the group and independently of g^a.
     */
    public SquareDH_Challenge(G generator, G a, G b) {
        this.generator = generator;
        this.a = a;
        this.b = b;
    }
}
