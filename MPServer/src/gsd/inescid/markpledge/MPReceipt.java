package gsd.inescid.markpledge;

import gsd.inescid.markpledge.interfaces.IMPReceipt;

import java.math.BigInteger;

public class MPReceipt implements IMPReceipt {
	protected BigInteger[][] receiptValidity;
	protected BigInteger challenge;
	protected BigInteger[] verificationCodes;
	protected byte[] voteHash;
	protected byte[] voteReceiptHash;
	protected byte[] signature;
	protected int rotation;
	

	
	/**
	 * Class full initialization constructor
	 * @param vCodes receipt verification codes
	 * @param rValidity receipt validation values
	 * @param challenge vote challenge
	 * @param voteHash the hash of the corresponding encrypted vote.
	 * @param voteReceiptHash the hash of the vote receipt.
	 * @param rotation the rotation necessary to align the receipt verification codes 
	 * 				   and the candidate vote encryptions to the voter's choice.
	 */
	public MPReceipt(BigInteger[] vCodes, BigInteger[][] rValidity, 
			BigInteger challenge, byte[] voteHash, byte[] voteReceiptHash, byte[] signature, int rotation)
	{
		this.verificationCodes = vCodes;
		this.receiptValidity = rValidity;
		this.challenge = challenge;
		this.voteHash = voteHash;
		this.voteReceiptHash = voteReceiptHash;
		this.signature = signature;
		this.rotation = rotation;
	}
	
	/**
	 * Constructor that only creates the structure to hold the verification 
	 * codes and receipt validity data for numberOfCandidates candidates.
	 * 
	 * @param numberOfCandidates the number of candidates running in the election.
	 */
	public MPReceipt(int numberOfCandidates)
	{
		this.verificationCodes = new BigInteger[numberOfCandidates];
		this.receiptValidity = new BigInteger[numberOfCandidates][];
	}
	
	/**
	 * Sets the rotation necessary to align the receipt verification codes 
	 * 				   and the candidate vote encryptions to the voter's choice. 
	 * @param rotation
	 */
	public void setRotation(int rotation)
	{
		this.rotation = rotation;
	}
	
	/**
	 * @return the rotation necessary to align the receipt verification codes 
	 * 				   and the candidate vote encryptions to the voter's choice.
	 */
	public int getRotation() {
		return this.rotation;
	}

	
	/**
	 * Set verification code for a candidate encryption
	 * @param vcode the verification code
	 * @param index verification code index. this index is the index of the 
	 * 				corresponding candidate vote encryption in the encrypted 
	 * 				vote WITHOUT applying the rotation.
	 */
	public void setVerificationCode(BigInteger vcode, int index)
	{
		this.verificationCodes[index] = vcode;
	}
	
	/**
	 * Set receipt validity data for a candidate encryption
	 * @param validity an array with the validity values
	 * @param index validity index. This index is the index of the 
	 * 				corresponding candidate vote encryption in the encrypted 
	 * 				vote WITHOUT applying the rotation.
	 */
	public void setValidity(BigInteger[] validity, int index)
	{
		this.receiptValidity[index] = validity;
	}
	
	/**
	 * Set the challenge value
	 * @param chal challenge value that originated the receipt
	 */
	public void setChallenge(BigInteger chal)
	{
		this.challenge = chal;
	}
	
	/**
	 * Set the vote hash
	 * @param hash the hash of the vote that corresponds to the receipt.
	 */
	public void setVoteHash(byte[] hash)
	{
		this.voteHash = hash;
	}
	
	/**
	 * Set the vote receipt hash
	 * @param hash the hash of the vote receipt.
	 */
	public void setVoteReceiptHash(byte[] hash)
	{
		this.voteReceiptHash = hash;
	}
	
	/**
	 * Set the signature over the vote receipt hash value as described in the computeHashCode method.
	 * @param signature
	 */
	public void setSignature(byte[] signature)
	{
		this.signature = signature;
	}
	
	/**
	 * @return the receipt validity codes
	 */
	public BigInteger[][] getReceiptValidity() {
		return this.receiptValidity;
	}
	
	/**
	 * @return the receipt verification codes
	 */
	public BigInteger[] getVerificationCodes() {
		return this.verificationCodes;
	}

	/**
	 * @return the vote challenge used to create the receipt
	 */
	public BigInteger getChallenge() {
		return this.challenge; 
	}

	/**
	 * @return the hash value of the corresponding encrypted vote.
	 */
	public byte[] getVoteHashCode(){
		return this.voteHash;
	}
	
	/**
	 * @return the hash value of the receipt.
	 */
	public byte[] getHash(){
		return this.voteHash;
	}
	
	/**
	 * @return the signature of over the vote hash concatenated with the hash of the receipt. 
	 */
	public byte[] getSignature(){
		return this.signature;
	}
	
	
	
	
	public String toString(String[] candidates)
	{
		StringBuilder s = new StringBuilder();
		s.append("COMPLETE VOTE RECEIPT\n(with verification proofs)\n");
		s.append("\nVote Challenge: " + challenge.toString(16).toUpperCase());
		s.append("\nVote Rotation: " + this.rotation);
		
		
		s.append("\n------------------------------------------------\n");
		s.append("Receipt with full verification codes ");
		s.append("\n------------------------------------------------\n");
		for(int i=0; i<this.verificationCodes.length; i++)
		{
			int k = (i- this.rotation);// % candidates.length;
			if (k<0)
				k+= candidates.length;
			
			s.append(candidates[i] + "\t");
			s.append(this.verificationCodes[k].toString(16).toUpperCase());
			s.append("\n");
		}

		s.append("\n------------------------------------------------\n");
		s.append("Receipt VALIDITY PROOF ");
		s.append("\n------------------------------------------------\n");
		for(int i=0; i<this.receiptValidity.length; i++)
		{
			int k = (i- this.rotation);
			if (k<0)
				k+= candidates.length;
			s.append("\nVerification code " + i + " validity proof\n");
			s.append("------------------------------------------------\n");
			for(int j=0; j < this.receiptValidity[k].length; j++)
			{
				//s.append("ElGamal Encryption: " + k + "\n");
				s.append(this.receiptValidity[k][j].toString(16).toUpperCase());
				s.append("\n");
			}
		}

		return s.toString();
	}
	

	


}
