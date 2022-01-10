package ddh;

/**
 * This class is a container object for a Decisional Diffie-Hellman challenge
 * tuple.
 * <p>
 * A DDH tuple consists of four group elements: a generator g, a second element
 * g^x, a third group element g^y and a fourth group element g^z. A DDH tuple
 * represents the problem of deciding whether the exponent of the fourth group
 * element is the product of the exponents of the second and third element.
 * <p>
 * I.e., a DDH tuple represents the problem of deciding whether z equals x * y
 * or if z was sampled uniformly and independently of x and y at random. When
 * given a DDH challenge (g, g^x, g^y, g^z) from a DDH challenger there is a 50%
 * probability, that (g, g^x, g^y, g^z) is a <b>real</b> DDH tuple, i.e., x and
 * y were drawn independently and uniformly at random and z = x * y, and a 50%
 * probability, that (g, g^x, g^y, g^z) is a <b>random</b> tuple, i.e., x, y and
 * z were all drawn uniformly and independently at random.
 * <p>
 * A correct solution for this DDH tuple is a boolean value which is true iff
 * this tuple is real, i.e., iff z = x * y.
 * 
 * @param G this type determines the type of group elements of this challenge.
 *          Ideally, G should equal IRandomGroupElement.
 */
public class DDH_Challenge<G> {
    /**
     * A generator of the group. Usually an encoding of one.
     */
    public final G generator;
    /**
     * A group element of the form g^x, where g is the generator in this tuple.
     * Usually, g^x was drawn uniformly random from the group.
     */
    public final G x;
    /**
     * A group element of the form g^y, where g is the generator in this tuple.
     * Usually, g^y was drawn uniformly random from the group.
     */
    public final G y;
    /**
     * A group element of the form g^z, where g is the generator in this tuple. This
     * tuple is a real DDH tuple iff z = x * y. If this tuple is not real,
     * then g^z was drawn uniformly from the group.
     */
    public final G z;

    /**
     * Creates a new DDH challenge.
     * 
     * @param generator A generator of the group.
     * @param x         A group element of the form g^x, where g is the generator in
     *                  this tuple.
     * @param y         A group element of the form g^y, where g is the generator in
     *                  this tuple.
     * @param z         A group element of the form g^z, where g is the generator in
     *                  this tuple. If z = x * y, then this object is a real DDH
     *                  tuple, otherwise it is a random tuple.
     */
    public DDH_Challenge(G generator, G x, G y, G z) {
        this.generator = generator;
        this.x = x;
        this.y = y;
        this.z = z;
    }
}
