package gsd.inescid.markpledge;

import gsd.inescid.markpledge.interfaces.IMPValidityProof;
import gsd.inescid.markpledge3.CGS97BallotValidity;

import java.math.BigInteger;

public class MPValidityProof implements IMPValidityProof {

	protected CGS97BallotValidity[] canonicalVoteProofs;
	protected BigInteger voteSumProof;
	
	
	
	public String toString()
	{
		StringBuilder s = new StringBuilder();
		s.append("Only ONE YESvote proof\n" +
				 this.voteSumProof.toString(16).toUpperCase());
		s.append("\n\nValidity proofs for the ballot entries\n" +
				"(without rotation)\n");
		
		for(int i=0; i<this.canonicalVoteProofs.length; i++)
		{
			s.append("\n------------------------------------------------\n");
			s.append("Proof of canonical vote " + i);
			s.append("\n------------------------------------------------\n");
			
			s.append(this.canonicalVoteProofs[i]);
		}
		return s.toString();
	}
	
	
	/**
	 * Creates a support structure for the specified number of candidates
	 * @param numberOfCandidates
	 */
	public MPValidityProof(int numberOfCandidates)
	{
		this.canonicalVoteProofs = new CGS97BallotValidity[numberOfCandidates];
	}
	
	/**
	 * Set the CGS97 canonical vote proofs 
	 * @param proofs
	 */
	public void setCanonicalVoteProofs(CGS97BallotValidity[] proofs)
	{
		this.canonicalVoteProofs = proofs;
	}
	
	/**
	 * Set the CGS97 canonical vote proof for a particular candidate vote 
	 * @param proof
	 * @param index index of the proof (i.e. candidate vote)
	 */
	public void setCanonicalVoteProof(CGS97BallotValidity proof, int index)
	{
		this.canonicalVoteProofs[index] = proof;
	}
	
	/**
	 * Set the encryption factor of the homomorphic canonical votes sum
	 * @param proof the homomorphic sum encryption factor
	 */
	public void setVoteSumProof(BigInteger proof)
	{
		this.voteSumProof = proof;
	}
	
	/**
	 * @return the CGS97 ballot validity proofs for the canonical votes.
	 */
	public CGS97BallotValidity[] getCanonicalVoteCGS97Proof() {
		return this.canonicalVoteProofs;
	}

	/**
	 * @return the encryption factor of the homomorphic sum of the canonical votes.
	 */
	public BigInteger getVoteSumProof() {
		return this.voteSumProof;
	}
}
