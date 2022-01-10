package basics;

/**
 * A generic interface for all reductons. The purpose of a reduction is to
 * algorithmically reduce the complexity of solving one problem to the
 * complexity of solving another problem. Therefore, a reduction is
 * simultaneously an adversary and a challenger.
 * <p>
 * As an adversary for a of problem of type A, a reduction implements a
 * {@code run} method which represents its starting point. When this run method
 * is called, the adversary will ask the challenger of type C for a problem
 * sample of type A. Since the reduction is itself a challenger it will be given
 * another adversary which can solve problems of type B. The task of the
 * reduction is to transform the problem of type A to a problem of type B which
 * can be solved by its adversary and then transform the solution to the problem
 * of type B to a olution to the problem of type A.
 * 
 * @param C determines the type of challenger (and therefore, indirectly, the
 *          type of challenges this reduction will solve).
 * @param S determines the type of solutions this reduction returns. If this
 *          reduction is to solve decisional problems then S should be Boolean.
 *          If this reduction is to solve computational problems like, e.g. RSA,
 *          then this type should be more complex, e.g. BigInteger.
 * 
 * @author Nico, Julia
 */
public interface IReduction<C extends IChallenger, S> extends IChallenger, IAdversary<C, S> {

}