package dlin;

/**
 * This class is a container object for a Decision Linear challenge tuple.
 * <p>
 * A DLin tuple consists of six group elements: a generator g, a second element
 * g^a, a third group element g^b, a fourth group element g^(a * u), a fifth
 * group element g^(b * v) and a sixth element g^w. A DLin tuple represents the
 * problem of deciding whether the exponent of the sixth group element is the
 * sum of the numbers u and v.
 * <p>
 * I.e., a DLin tuple represents the problem of deciding whether w equals u * v
 * or if w was sampled uniformly and independently of a, b, u and v at random.
 * When given a DLin challenge (g, g^a, g^b, g^(a * u), g^(b * v), g^w) from a
 * DLin challenger there is a 50% probability, that (g, g^a, g^b, g^(a * u),
 * g^(b * v), g^w) is a <b>real</b> DLin tuple, i.e., a, b, u and v were drawn
 * independently and uniformly at random and w = u + v, and a 50% probability,
 * that (g, g^a, g^b, g^(a * u), g^(b * v), g^w) is a <b>random</b> tuple, i.e.,
 * a, b, u, v and w were all drawn uniformly and independently at random.
 * <p>
 * A correct solution for this DLin tuple is a boolean value which is true iff
 * this tuple is real, i.e., iff w = u + v.
 * 
 * @param G this type determines the type of group elements of this challenge.
 *          Ideally, G should equal IRandomGroupElement.
 */
public class DLin_Challenge<G> {
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
     * A group element of the form g^b, where g is the generator in this tuple.
     * Usually, g^b was drawn uniformly random from the group.
     */
    public final G b;
    /**
     * A group element of the form g^(a * u), where g is the generator in this
     * tuple. Usually, a and u have been drawn uniformly and independently at random
     * from Z/pZ.
     */
    public final G aTimesU;
    /**
     * A group element of the form g^(b * v), where g is the generator in this
     * tuple. Usually, b and v have been drawn uniformly and independently at random
     * from Z/pZ.
     */
    public final G bTimesV;
    /**
     * A group element of the form g^w, where g is the generator in this tuple. This
     * tuple is a real DLin tuple iff w = u +v. If this tuple is not real, then g^w
     * was drawn uniformly from the group and independently from all other group
     * elements.
     */
    public final G w;

    /**
     * Creates a new DLin challenge.
     * 
     * @param generator A generator of the group. Usually an encoding of one.
     * @param a         A group element of the form g^a, where g is the generator in
     *                  this tuple. Usually, g^a was drawn uniformly random from the
     *                  group.
     * @param b         A group element of the form g^b, where g is the generator in
     *                  this tuple. Usually, g^b was drawn uniformly random from the
     *                  group.
     * @param aTimesU   A group element of the form g^(a * u), where g is the
     *                  generator in this tuple. Usually, a and u have been drawn
     *                  uniformly and independently at random from Z/pZ.
     * @param bTimesV   A group element of the form g^(b * v), where g is the
     *                  generator in this tuple. Usually, b and v have been drawn
     *                  uniformly and independently at random from Z/pZ.
     * @param w         A group element of the form g^w, where g is the generator in
     *                  this tuple. This tuple is a real DLin tuple iff w = u +v. If
     *                  this tuple is not real, then g^w was drawn uniformly from
     *                  the group and independently from all other group elements.
     */
    public DLin_Challenge(G generator, G a, G b, G aTimesU, G bTimesV, G w) {
        this.generator = generator;
        this.a = a;
        this.b = b;
        this.aTimesU = aTimesU;
        this.bTimesV = bTimesV;
        this.w = w;
    }
}
