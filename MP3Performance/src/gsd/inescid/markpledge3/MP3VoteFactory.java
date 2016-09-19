package gsd.inescid.markpledge3;

import gsd.inescid.crypto.util.CryptoUtil;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class MP3VoteFactory {
	
	
	public final MP3Parameters PARAMETERS;
	public final String HASH_ALGORITHM;
	public final boolean WITH_VALIDITY;
	private final Random RANDOM; 
	private MP3PreparedVote preparedVote=null;
	
	/**
	 * Initializes a MarkPledge3VoteFactory
	 * @param param MarkPledgeParameters used in the vote encryption. 
	 * The randomness source of the public key in the MarkPledge parameters MUST have already been initialized. 
	 * If not initialized the default SecureRandom implementation will be used for the random encryption factors generation.  
	 * @param hashAlgorithm hash algorithm to be used as a commitment scheme to the vote encryption
	 * @param r randomness source
	 */
	public MP3VoteFactory(MP3Parameters param, String hashAlgorithm, Random r, boolean validity)
	{
		this.RANDOM = r;
		this.PARAMETERS = param;
		this.HASH_ALGORITHM = hashAlgorithm;
		this.WITH_VALIDITY = validity;
	}
	
	/**
	 * Initializes a MarkPledge3VoteFactory.
	 * It uses the default SecureRandom provider as randomness source
	 * @param param MarkPledgeParameters used in the vote encryption.
	 * The randomness source of the public key in the MarkPledge parameters MUST have already been initialized. 
	 * If not initialized the default SecureRandom implementation will be used for the random encryption factors generation.  
	 * @param hashAlgorithm hash algorithm to be used as a commitment scheme to the vote encryption
	 */
	public MP3VoteFactory(MP3Parameters param, String hashAlgorithm, boolean validity)
	{
		this.RANDOM = new SecureRandom();
		this.PARAMETERS = param;
		this.HASH_ALGORITHM = hashAlgorithm;
		this.WITH_VALIDITY = validity;
	}
	
	
	/**
	 * Prepares a new MarkPledge vote
	 * @param n number of candidates in the ballot
	 * @throws NoSuchAlgorithmException 
	 */
	public final void prepareVote(int n) throws NoSuchAlgorithmException
	{
		BigInteger pledge = CryptoUtil.generateRandomNumber(this.PARAMETERS.ELECTION_PUBLIC_KEY.q, this.RANDOM);
		prepareVote(n, pledge);
	}
	
	/**
	 * Prepares a new MarkPledge vote
	 * @param n number of candidates in the ballot
	 * @param pledge pledge value to use in the vote preparation
	 * @throws NoSuchAlgorithmException 
	 */
	public final void prepareVote(int n, BigInteger pledge) throws NoSuchAlgorithmException
	{
		this.preparedVote = new MP3PreparedVote(this.PARAMETERS, n, pledge, this.RANDOM, this.WITH_VALIDITY, this.HASH_ALGORITHM);
	}
	
	/**
	 * Method to obtain the pledge value on the prepared vote
	 * @return the pledge value
	 * @throws NullPointerException if no prepared vote exists
	 */
	public final BigInteger getPledgeValue()
	{
		return this.preparedVote.PLEDGE_VALUE;
	}
	
	/**
	 * This method return the MarkPledge3 vote and receipt from the prepared vote
	 * @param challenge the challenge to the prepared vote encryption
	 * @param selectionIndex the selected candidate index (0 to number of candidates -1)
	 * @return a MarkPledge 3 vote and receipt
	 * @throws NullPointerException if no prepared vote exists
	 */
	public final MP3VoteAndReceipt getVoteAndReset(BigInteger challenge, int selectionIndex)
	{
		MP3VoteAndReceipt finalVote = this.preparedVote.getVoteAndReceipt(challenge, selectionIndex);
		this.preparedVote = null;
		return finalVote;
	}
	
	
	/**
	 * THIS METHOD SHOULD ONLY BE USED FOR TEST PROGRAMS because the challenge is internally generated.
	 * The method return the MarkPledge3 vote and receipt from the prepared vote
	 * The challenge is randomly selected using this object random number generator
	 * @param selectionIndex the selected candidate index
	 * @return a MarkPledge 3 vote and receipt
	 * @throws NullPointerException if no prepared vote exists
	 */
	public final MP3VoteAndReceipt getVoteAndReset(int selectionIndex)
	{
		BigInteger challenge = CryptoUtil.generateRandomNumber(this.PARAMETERS.ELECTION_PUBLIC_KEY.q, this.RANDOM);
		MP3VoteAndReceipt finalVote = this.preparedVote.getVoteAndReceipt(challenge, selectionIndex);
		this.preparedVote = null;
		return finalVote;
	}
	
	
	
	
	/**
	 * This method returns the hash of the encryptions of the prepared vote (no random factors, nor verification values)
	 * @return the hash of the prepared vote (only candidate vote and commit encryptions are considered)
	 * @throws NoSuchAlgorithmException 
	 * @throws NullPointerException if no prepared vote exists
	 * @throws NoSuchAlgorithmException if the HASH_ALGORITHM is not supported
	 */
	public final byte[] getPreparedVoteHash() throws NoSuchAlgorithmException
	{
		return preparedVote.getHash(this.HASH_ALGORITHM);
	}
	
	
	/**
	 * This method returns the hash of an array of MP3CandidateVoteEncryptions.
	 * It takes into account only the encryption of the candidate vote (X and Y)
	 * and the encryption of the commit value (X and Y) and following this order.
	 * The X and Y BigInteger components of the encryptions are transformed to
	 * byte arrays using the method toByteArray of the BigInteger class. 
	 * @param candidateVotes the MarkPledge3 candidate vote encryption array
	 * @param hashAlgorithm the hash algorithm
	 * @return the hash value
	 * @throws NoSuchAlgorithmException if the hashAlgorithm is not supported
	 */
	public static final byte[] getCandideVotesHash(MP3CandidateVoteEncryption[] candidateVotes, String hashAlgorithm) throws NoSuchAlgorithmException
	{
		MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
		md.reset();
		for(int i=0; i < candidateVotes.length; i++)
		{
			md.update(candidateVotes[i].BIT_ENCRYPTION.X.toByteArray());
			md.update(candidateVotes[i].BIT_ENCRYPTION.Y.toByteArray());
			md.update(candidateVotes[i].COMMIT_ENCRYPTION.X.toByteArray());
			md.update(candidateVotes[i].COMMIT_ENCRYPTION.Y.toByteArray());
		}

		return md.digest();
	}
	
	
}
