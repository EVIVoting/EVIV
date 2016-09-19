package gsd.inescid.markpledge3;

import java.math.BigInteger;

import gsd.inescid.crypto.ElGamalVerifiableEncryption;

public class MP3PreparedCandidateVote implements Comparable<MP3PreparedCandidateVote>{

	private enum InternalState { LOCKED, UNLOCKED };
	
	private InternalState state;
	
	public final ElGamalVerifiableEncryption BIT_ENCRYPTION;
	public final CGS97BallotValidity BIT_ENCRYPTION_VALIDITY;
	public final ElGamalVerifiableEncryption COMMIT_ENCRYPTION;
	
	public final BigInteger COMMIT_VALUE;
	public final boolean YES_VOTE;
	
	private MP3VerificationValues verificationValues;
	
	public MP3PreparedCandidateVote (boolean yesVote, ElGamalVerifiableEncryption bitEncryption, CGS97BallotValidity validity, 
			ElGamalVerifiableEncryption commitmentEncryption, BigInteger commitment)
	{
		this.BIT_ENCRYPTION = bitEncryption;
		this.BIT_ENCRYPTION_VALIDITY = validity;
		this.COMMIT_ENCRYPTION = commitmentEncryption;
		this.COMMIT_VALUE = commitment;
		this.YES_VOTE = yesVote;
		
		this.state = InternalState.UNLOCKED;
	}
	
	/**
	 * This method builds and returns the final candidate encryption 
	 * @param chal the challenge to test the candidate encryption
	 * @param q modulus of the verification domain
	 * @return the candidate encryption
	 */
	public final MP3CandidateVoteEncryption getCandidateEncryption(BigInteger chal, BigInteger q)
	{
		setVerificationValues(q, chal);
		return new MP3CandidateVoteEncryption(
				this.BIT_ENCRYPTION.MESSAGE_ENCRYPTION,
				this.BIT_ENCRYPTION_VALIDITY,
				this.COMMIT_ENCRYPTION.MESSAGE_ENCRYPTION,
				this.verificationValues.VERIFICATION_VALUE, 
				this.verificationValues.ENCRYPTION_FACTOR);
	}
	
	/**
	 * Calculates the verification values for this candidate encryption based on the received parameters: 
	 * IMPORTANT NOTE: the verification values are only calculated the first time this method is invoked. 
	 * 				   In subsequent calls the method returns the same values of the first call;
	 * @param q modulus of the verification domain
	 * @param chal challenge to the vote encryption
	 * @return the verification values
	 */
	private final void setVerificationValues(BigInteger q, BigInteger chal)
	{
		if(this.state == InternalState.UNLOCKED)
		{
			this.state = InternalState.LOCKED;
			
			BigInteger encryptedValueForVerification;
			BigInteger encryptionFactorForVerification;
						
			if(YES_VOTE)
				encryptedValueForVerification = this.COMMIT_VALUE;
			else{
				BigInteger two = new BigInteger("2");
				encryptedValueForVerification = (this.COMMIT_VALUE.add(
						two.multiply(chal.subtract(this.COMMIT_VALUE)))).mod(q);	
			}
			
			encryptionFactorForVerification = (((chal.subtract(encryptedValueForVerification)
					).multiply(this.BIT_ENCRYPTION.ENCRYPTION_FACTOR)
					).add(this.COMMIT_ENCRYPTION.ENCRYPTION_FACTOR)).mod(q);	
			
			this.verificationValues = new MP3VerificationValues(encryptedValueForVerification, encryptionFactorForVerification);
		}
	}
	
	
	public String toString()
	{
		String s = "\nMarkPledge3 prepared candidate vote encryption (" + ((this.YES_VOTE)? "YES":"NO") + "-vote):"
				 + "\nCandidate vote encryption:\n" + this.BIT_ENCRYPTION
				 + "\n------------------------------------------------"
				 + "\nCommit encryption:\n" + this.COMMIT_ENCRYPTION
				 + "\n------------------------------------------------"
				 + "\nCommit value = " + this.COMMIT_VALUE
				 + "\n------------------------------------------------"
				 + "\n" + this.verificationValues
				 + "\n------------------------------------------------\n";
		return s;
	}

	
	/**
	 * Compares this object with other MarkPledge3PreparedCandidateVote using the values X of 
	 * the encryption (starting with the value of the CANDIDATE_ENCRYPTION).   
	 */
	public int compareTo(MP3PreparedCandidateVote obj)
	{
		int result = this.BIT_ENCRYPTION.MESSAGE_ENCRYPTION.X.compareTo(
				obj.BIT_ENCRYPTION.MESSAGE_ENCRYPTION.X);
		
		if(result!=0)
			return result;
		else 
			return this.COMMIT_ENCRYPTION.MESSAGE_ENCRYPTION.X.compareTo(
					obj.COMMIT_ENCRYPTION.MESSAGE_ENCRYPTION.X);
	}
	
}
