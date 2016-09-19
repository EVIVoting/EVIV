package gsd.inescid.markpledge3;

import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.Arrays;

import gsd.inescid.crypto.ElGamalVerifiableEncryption;
import gsd.inescid.crypto.util.CryptoUtil;


public class MP3PreparedVote {

	private enum InternalState { LOCKED, UNLOCKED };
	
	private InternalState state;
	private MP3VoteAndReceipt finalVote;
	
	private final MP3PreparedCandidateVote[] PREPARED_CANDIDATE_VOTES;
	public final BigInteger PLEDGE_VALUE;
	private final int YES_VOTE_INDEX;
	private final MP3Parameters MP3_PARAMETERS;
	public final boolean WITH_VALIDITY;
	public final String HASH_FUNCTION;
	
	
	/**
	 * Prepares a MarkPledge3 vote
	 * @param param MarkPledge3 public election parameters
	 * @param nCandidates number of candidates running in election (must be >=2)
	 * @param pledgeValue pledge value to use in the vote preparation
	 * @param r source of randomness to use in the vote preparation
	 * @param validity if true a validity proof is created
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidParameterException if nCandidades < 2
	 */
	public MP3PreparedVote(MP3Parameters param, int nCandidates, BigInteger pledgeValue, Random r, boolean validity, String hashFunction) throws NoSuchAlgorithmException
	{
		if(nCandidates<2)
			throw new InvalidParameterException("Number of candidates must be >= 2.");

		this.WITH_VALIDITY = validity;
		this.HASH_FUNCTION = hashFunction;
		this.state = InternalState.UNLOCKED;
		this.MP3_PARAMETERS = param;
		this.PREPARED_CANDIDATE_VOTES = new MP3PreparedCandidateVote[nCandidates];
		
		this.PLEDGE_VALUE = pledgeValue;
		this.PREPARED_CANDIDATE_VOTES[0] = getYesVote(this.PLEDGE_VALUE,r);
	
		MP3PreparedCandidateVote[] noVotes = getNoVoteArray(nCandidates-1, r);
		for(int i=1, j=0; i<this.PREPARED_CANDIDATE_VOTES.length && j<noVotes.length; i++, j++)
			this.PREPARED_CANDIDATE_VOTES[i] = noVotes[j];
		
		Arrays.sort(this.PREPARED_CANDIDATE_VOTES);
		//lookup yes-vote
		for(int i=0; i<this.PREPARED_CANDIDATE_VOTES.length; i++)
			if(this.PREPARED_CANDIDATE_VOTES[i].YES_VOTE)
			{
				this.YES_VOTE_INDEX = i;
				return;
			}
		//this should not happen
		this.YES_VOTE_INDEX = -1;
	}
	
	/**
	 * Builds a "yes-vote" MP3PreparedCandidateVote for the given pledgeValue 
	 * @param pledgeValue
	 * @param r randomness source
	 * @return a prepared "yes-vote"
	 * @throws NoSuchAlgorithmException 
	 */
	private final MP3PreparedCandidateVote getYesVote(BigInteger pledgeValue, Random r) throws NoSuchAlgorithmException{
		
		ElGamalVerifiableEncryption commiEnc  = this.MP3_PARAMETERS.ELECTION_PUBLIC_KEY.encryptVerifiableQOrderMessage(
				this.MP3_PARAMETERS.BASE_VOTE_GENERATOR.modPow(pledgeValue, this.MP3_PARAMETERS.ELECTION_PUBLIC_KEY.p));
		ElGamalVerifiableEncryption cvEnc = this.MP3_PARAMETERS.ELECTION_PUBLIC_KEY.encryptVerifiableQOrderMessage(
				this.MP3_PARAMETERS.BASE_VOTE_GENERATOR);
		// create validity proof data
		CGS97BallotValidity validity;
		if(this.WITH_VALIDITY)
			validity = new CGS97BallotValidity(true, cvEnc, this.MP3_PARAMETERS.ELECTION_PUBLIC_KEY, 
					this.MP3_PARAMETERS.BASE_VOTE_GENERATOR, r, this.HASH_FUNCTION);
		else
			validity = null;
		
		MP3PreparedCandidateVote yesVote = new MP3PreparedCandidateVote(true, cvEnc, validity, commiEnc, pledgeValue);
		return yesVote;
	}
	
	/**
	 * Builds a "no-vote" array of MP3PreparedCandidateVote with the given length 
	 * @param n array length
	 * @param r randomness source
	 * @return a prepared "no-vote" array
	 * @throws NoSuchAlgorithmException 
	 */
	private final MP3PreparedCandidateVote[] getNoVoteArray(int n, Random r) throws NoSuchAlgorithmException{
		ElGamalVerifiableEncryption commiEnc;
		ElGamalVerifiableEncryption cvEnc;
		MP3PreparedCandidateVote[] noVotes = new MP3PreparedCandidateVote[n];
		BigInteger[] commit = getNewCommits(n, r);
				
		for(int i=0; i<noVotes.length; i++)
		{
			commiEnc  = this.MP3_PARAMETERS.ELECTION_PUBLIC_KEY.encryptVerifiableQOrderMessage(
					this.MP3_PARAMETERS.BASE_VOTE_GENERATOR.modPow(commit[i], this.MP3_PARAMETERS.ELECTION_PUBLIC_KEY.p));
			cvEnc = this.MP3_PARAMETERS.ELECTION_PUBLIC_KEY.encryptVerifiableQOrderMessage(
					this.MP3_PARAMETERS.BASE_VOTE_GENERATOR_INVERSE);
			// create validity proof data
			CGS97BallotValidity validity;
			if(this.WITH_VALIDITY)
				validity = new CGS97BallotValidity(false, cvEnc, this.MP3_PARAMETERS.ELECTION_PUBLIC_KEY, 
						this.MP3_PARAMETERS.BASE_VOTE_GENERATOR_INVERSE, r, this.HASH_FUNCTION);
			else
				validity = null;
			
			noVotes[i] = new MP3PreparedCandidateVote(false, cvEnc, validity, commiEnc, commit[i]);
		}

		return noVotes;
	}
	
	/**
	 * Generates n different commit values (also different from PLEDGE_VALUE
	 * @param n
	 * @param r randomness source
	 * @return new commit values
	 */
	private final BigInteger[] getNewCommits(int n, Random r)
	{
		BigInteger[] newCommits = new BigInteger[n];	
		boolean exists;
		for(int i=0; i<newCommits.length; i++)
		{
			newCommits[i] = CryptoUtil.generateRandomNumber(this.MP3_PARAMETERS.ELECTION_PUBLIC_KEY.q, r);
			//test for equality
			exists=false;
			for(int k=0; k<i; k++)
			{
				if(newCommits[k].equals(newCommits[i]))
				{
					exists=true;
					break;
				}
			}
			if(exists || newCommits[i].equals(this.PLEDGE_VALUE))
				i--; //forces new value for newCommits[i]		
		}
		
		return newCommits;
	}
	
	
	/**
	 * Builds the public/voter verifiable vote encryption based on the challenge received.
	 * THIS METHOD SHOULD ONLY BE CALLED ONCE because the MP3CandidateVoteEncryption 
	 * only opens for the first time(first value of chal). The subsequent calls will return 
	 * the value of the first call, i.e. the chal and selectionIndex of the 2º and 
	 * subsequent calls are ignored.
	 * @param chal 
	 * @param selectionIndex the index of the selected candidate (0 to number of candidates -1)
	 * @return the public/voter verifiable vote encryption
	 */
	public final MP3VoteAndReceipt getVoteAndReceipt(BigInteger chal, int selectionIndex)
	{
		if(this.state.equals(InternalState.UNLOCKED))
		{
			this.state = InternalState.LOCKED;
			this.prepareVoteAndReceipt(chal, selectionIndex);
		}
		return this.finalVote;
	}
	
	/**
	 * Builds the public/voter verifiable vote encryption based on the challenge received.
	 * This method should only be called once because the MP3CandidateVoteEncryption 
	 * only opens for the first time/first value of chal.
	 * @param chal 
	 * @param selectionIndex the index of the selected candidate (0 to number of candidates -1)
	 */
	
	private final void prepareVoteAndReceipt(BigInteger chal, int selectionIndex)
	{
		MP3CandidateVoteEncryption[] finalVotes = new MP3CandidateVoteEncryption[this.PREPARED_CANDIDATE_VOTES.length];
		BigInteger voteValidityRandomFactor = this.WITH_VALIDITY ? BigInteger.ZERO : null;
			
		for(int i=0; i<finalVotes.length; i++)
		{
			finalVotes[i] = this.PREPARED_CANDIDATE_VOTES[i].getCandidateEncryption(chal, 
					this.MP3_PARAMETERS.ELECTION_PUBLIC_KEY.q);
			if (this.WITH_VALIDITY)
				voteValidityRandomFactor = voteValidityRandomFactor.add(this.PREPARED_CANDIDATE_VOTES[i].BIT_ENCRYPTION.ENCRYPTION_FACTOR);
		}
		int rotation = (this.YES_VOTE_INDEX - selectionIndex) % this.PREPARED_CANDIDATE_VOTES.length;
		if (rotation < 0) rotation = this.PREPARED_CANDIDATE_VOTES.length + rotation;
		voteValidityRandomFactor = voteValidityRandomFactor.mod(this.MP3_PARAMETERS.ELECTION_PUBLIC_KEY.q);
		this.finalVote = new MP3VoteAndReceipt(finalVotes, chal, rotation, voteValidityRandomFactor);
	}
	
	
	/**
	 * This method returns the hash of the encryptions of the prepared
	 * vote (no random factors, nor verification values). It uses the 
	 * method getCandideVotesHash of the MP3VoteFactory class
	 * @param hashAlgorithm hash algorithm
	 * @return the hash of the prepared vote (only candidate vote and commit encryptions are considered)
	 * @throws NoSuchAlgorithmException if the hashAlgorithm is not supported
	 */
	public final byte[] getHash(String hashAlgorithm) throws NoSuchAlgorithmException
	{
		// test if is necessary to build the candidate encryption array
		if(this.state.equals(InternalState.UNLOCKED))
		{
			MP3CandidateVoteEncryption[] cvArray = new MP3CandidateVoteEncryption[this.PREPARED_CANDIDATE_VOTES.length];
			for(int i=0; i < cvArray.length; i++)
			{
				cvArray[i] = new MP3CandidateVoteEncryption(this.PREPARED_CANDIDATE_VOTES[i].BIT_ENCRYPTION.MESSAGE_ENCRYPTION,
															this.PREPARED_CANDIDATE_VOTES[i].BIT_ENCRYPTION_VALIDITY,
															this.PREPARED_CANDIDATE_VOTES[i].COMMIT_ENCRYPTION.MESSAGE_ENCRYPTION,
															null, null);
			}
			return MP3VoteFactory.getCandideVotesHash(cvArray, hashAlgorithm);
		} else 
			return this.finalVote.getHash(hashAlgorithm);
	}
}
