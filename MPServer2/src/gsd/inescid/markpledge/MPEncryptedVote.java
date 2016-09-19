package gsd.inescid.markpledge;

import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.markpledge.interfaces.IMPEncryptedVote;

/**
 * MarkPledge encrypted vote container class. 
 * 
 * @author Rui Joaquim
 *
 */
public class MPEncryptedVote implements IMPEncryptedVote{

	/**
	 * Array to hold the encrypted vote.
	 * Each entry holds the ElGamal encryptions that correspond to a candidate vote.
	 */
	private ElGamalEncryption[][] encryptedVote;
	private byte[] signature;
	private byte[] hashCode;
	private boolean isChainHash;
	
	
	public MPEncryptedVote(int numberOfCandidates){
		this.encryptedVote = new ElGamalEncryption[numberOfCandidates][];
	}

	public String toString()
	{
		StringBuilder s = new StringBuilder();
		s.append("VOTE ENCRYPTION\n");
		for(int i=0; i<this.encryptedVote.length; i++)
		{
			s.append("------------------------------------------------\n");
			s.append("Candidate encryption ");
			s.append(i);
			s.append("\n");
			s.append("------------------------------------------------\n");
			for(int k=0; k < this.encryptedVote[i].length; k++)
			{
				//s.append("ElGamal Encryption: " + k + "\n");
				s.append(this.encryptedVote[i][k].toString());
				s.append("\n");
			}
		}
		return s.toString();
	}
	 
	
	 /**
	  * Sets the hash of the encrypted vote
	  * @param hashCode
	  * @param isChainHash true is the hashCode was performed using the hash chain method.
	  */
	 public void setHash(byte[] hashCode, boolean isChainHash)
	 {
		 this.hashCode = hashCode;
		 this.isChainHash = isChainHash;
	 }
	 
	 /**
	  * @return the hash code of this vote
	  */
	 public byte[] getHash()
	 {
		 return this.hashCode;
	 }
	 
	 /**
	  * @return true if the hash of this vote was computed using the hash chaining method.
	  */
	 public boolean isChainHash()
	 {
		 return this.isChainHash;
	 }
	 
	 
	/**
	 * Sets the vote signature
	 * @param voteSignature vote signature, i.e. signature over the hash of the encryptedVote
	 */
	public void setSignature(byte[] voteSignature)
	{
		this.signature = voteSignature;
	}
	
	/**
	 * @return the vote encryption signature
	 */
	public byte[] getSignature() {
		return this.signature;
	}
	
	/**
	 * Stores a candidate vote encryption.
	 * @param candidateIndex candidate encryption index.
	 * @param candidateVote candidate encryption.
	 */
	public void setCandidateVote(int candidateIndex, ElGamalEncryption[] candidateVote)
	{
		this.encryptedVote[candidateIndex] = candidateVote;
	}
	
	/**
	 * @return an array of candidate encryptions. Each candidate encryption is an array
	 * 		   of ElGamalEncryptions. 
	 */
	public ElGamalEncryption[][] getEncryptedVote() {
		return this.encryptedVote;
	}

	/**
	 * @param candidateEncryptionIndex the index of the desired candidate vote encryption.
	 * @return an array with the ElGamal encryptions that represents 
	 * 		   the selected candidate encryption.
	 */
	public ElGamalEncryption[] getCandidateEncryption(int candidateEncryptionIndex) {
		return this.encryptedVote[candidateEncryptionIndex];
	}

	
	

}
