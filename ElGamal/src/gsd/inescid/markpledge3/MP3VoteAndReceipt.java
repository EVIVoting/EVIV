package gsd.inescid.markpledge3;

import gsd.inescid.crypto.util.Base64;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

public class MP3VoteAndReceipt {

	public final MP3CandidateVoteEncryption[] CANDIDATE_VOTES;
	public final BigInteger CHALLENGE;
	public final int FIRST_CANDIDATE_INDEX;
	public final BigInteger VOTE_VALIDITY;
	
	// XML TAGS
	public static final String XML_TAG = "MP3VoteAndReceipt";
	public static final String XML_CANDIDATE_VOTES_TAG = "CandidateVotes";
	public static final String XML_CHALLENGE_TAG = "Challenge";
	public static final String XML_VOTE_VALIDITY_TAG = "VoteValidity";
	
	public String toXML()
	{
		StringBuilder xml = new StringBuilder();
		xml.append(xml + "<" + XML_TAG + ">\n");
		xml.append("<" + XML_CANDIDATE_VOTES_TAG + ">\n");
		for(int i=0, j = this.FIRST_CANDIDATE_INDEX; i < this.CANDIDATE_VOTES.length; i++, j++)
		{
			if(j == this.CANDIDATE_VOTES.length)
				j=0;
			xml.append(this.CANDIDATE_VOTES[j].toXML());
		}
		xml.append("</" + XML_CANDIDATE_VOTES_TAG + ">\n");
		xml.append("<" + XML_CHALLENGE_TAG + ">" + Base64.encode(this.CHALLENGE.toByteArray()) + "</" + XML_CHALLENGE_TAG + ">\n");
		xml.append("<" + XML_VOTE_VALIDITY_TAG + ">" + Base64.encode(this.VOTE_VALIDITY.toByteArray()) + "</" + XML_VOTE_VALIDITY_TAG + ">\n");
		xml.append(xml + "</" + XML_TAG + ">\n");
		return xml.toString();
	}
	
	
	/**
	 * Constructor
	 * @param candidateVotes 
	 * @param chal
	 * @param firstCandidateIndex the rotation necessary to adjust the candidateVotes (which are numerically ordered) to the voter selection
	 * @param voteValidity the encryption factor of the homomorphic sum of all candidate votes
	 */
	public MP3VoteAndReceipt (MP3CandidateVoteEncryption[] candidateVotes, BigInteger chal, int firstCandidateIndex, BigInteger voteValidity)
	{
		this.CANDIDATE_VOTES = candidateVotes;
		this.CHALLENGE = chal;
		this.FIRST_CANDIDATE_INDEX = firstCandidateIndex;
		this.VOTE_VALIDITY = voteValidity;
	}
	
	
	/**
	 * This method returns the hash of the encryptions of the vote
	 * (no random factors, nor verification values). It uses the 
	 * method getCandideVotesHash of the MP3VoteFactory class
	 * @param hashAlgorithm hash algorithm
	 * @return the hash of the vote (only candidate vote and commit encryptions are considered)
	 * @throws NoSuchAlgorithmException if the hashAlgorithm is not supported
	 */
	public final byte[] getHash(String hashAlgorithm) throws NoSuchAlgorithmException
	{
		return MP3VoteFactory.getCandideVotesHash(this.CANDIDATE_VOTES, hashAlgorithm);
	}
	
	
	/**
	 * This method return a textual representation of the vote receipt.
	 * The candidates are labeled by letters starting at letter 'A'. 
	 * @return textual representation of the vote receipt
	 */
	public final String getReceipt()
	{
		String[] labels = new String[this.CANDIDATE_VOTES.length];
		char candidateLabel = 'A';
		for(int i=0; i<labels.length; i++, candidateLabel++)
			labels[i] = Character.toString(candidateLabel);
		return getReceipt(labels);
	}
	
	/**
	 * This method return a textual representation of the vote receipt.
	 * The candidates are labeled accordingly to the received labels.
	 * @param candidateLabels the candidates labels
	 * @return textual representation of the vote receipt
	 */
	public final String getReceipt(String[] candidateLabels)
	{
		String s = "\nVote Receipt";
		for(int i=0, r=this.FIRST_CANDIDATE_INDEX; i<this.CANDIDATE_VOTES.length; i++, r=(++r%this.CANDIDATE_VOTES.length))
			s += "\n" + candidateLabels[i] + " - " + this.CANDIDATE_VOTES[r].VERIFICATION_VALUE;
		
		s += "\nVote challenge\n" + this.CHALLENGE;
		return s;
	}
	
}
