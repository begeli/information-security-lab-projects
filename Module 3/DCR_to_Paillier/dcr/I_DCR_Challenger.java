package dcr;

import basics.IChallenger;

/**
 * A DCR challenger provides DCR challenges and plays the security game of the
 * DCR assumption with implementations of the {@code I_DCR_Adversary} interface.
 * It has a method {@code getChallenge()} which will be called by a DCR
 * adversary and which provides the DCR challenge in the corresponding security
 * game.
 * 
 * @author Nico
 */
public interface I_DCR_Challenger extends IChallenger {
    /**
     * Returns the challenge of this challenger. This method should always return
     * the same challenge, no matter how often it has been called.
     * 
     * @return the challenge of this challenger.
     */
    DCR_Challenge getChallenge();
}
