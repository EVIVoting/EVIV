package gsd.inescid.markpledge;

import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.markpledge.interfaces.IMPEncryptedVote;
import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.interfaces.IMPReceipt;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;
import gsd.inescid.markpledge.interfaces.IMPVoteAndReceipt;

import java.math.BigInteger;
import java.security.MessageDigest;

/**
 * Container class to hold a MarkPledge vote encryption and corresponding receipt.
 * 
 * @author Rui Joaquim
 */
public abstract class MPAbstractVoteAndReceipt implements IMPVoteAndReceipt {
	
	protected IMPEncryptedVote voteEnc;
	protected IMPReceipt receipt;
	protected IMPValidityProof validityProofs;
	
	/**
	 * Default constructor
	 */
	public MPAbstractVoteAndReceipt(){};
	
	/**
	 * This constructor DOES NOT verify if the vote and receipt receive are a match
	 * nor if they are valid, nor verifies any other proofs.
	 * There are specific methods (verifyReceipt and verifyReceiptAndCanonicalVote)
	 * to validate the receipt and/or the vote. 
	 * 
	 * @param vote the vote encryption
	 * @param receipt the vote receipt
	 * @param voteValidityProof the vote validity proofs (necessary to perform an homomorphic vote tally)
	 */
	public MPAbstractVoteAndReceipt(IMPEncryptedVote vote, IMPReceipt receipt, IMPValidityProof voteValidityProof)
	{
		this.voteEnc = vote;
		this.receipt = receipt;
		this.validityProofs = voteValidityProof;
	}
	
	
	/**
	 * Set the vote encryption
	 * @param voteEnc
	 */
	public void setEncryptedVote(IMPEncryptedVote voteEnc)
	{
		this.voteEnc = voteEnc;
	}
	
	/**
	 * Set the vote receipt
	 * @param receip
	 */
	public void setReceipt(IMPReceipt receipt)
	{
		this.receipt = receipt;
	}
	

	
	/**
	 * @return the container's vote encryption
	 */
	public IMPEncryptedVote getVoteEncryption(){
		return this.voteEnc;
	}
	
	/**
	 * @return the container's vote receipt
	 */
	public IMPReceipt getVoteReceipt(){
		return this.receipt;
	}

	/**
	 * @return the container's vote validity proof
	 */
	public IMPValidityProof getVoteValidityProof(){
		return this.validityProofs;
	}


	/**
	 * The return of this method is the first encryption of the vote candidate encryptions.
	 * This works for MP1A and MP3 but it must be redefined for MP1 and MP2.
	 * 
	 * @param param MarkPledge parameters, as they are needed to transform the encrypted vote into 
	 * the canonical vote in MP1 and MP2.
	 * @return the canonical vote corresponding to the encrypted vote (only valid for MP1 and MP3)
	 */
	public ElGamalEncryption[] getCanonicalVote(IMPParameters param)
	{
		ElGamalEncryption[][] candidateEncryptions = this.voteEnc.getEncryptedVote();
		ElGamalEncryption[] canonicalVote = new ElGamalEncryption[candidateEncryptions.length];
		for(int i=0; i<canonicalVote.length; i++)
			canonicalVote[i] = candidateEncryptions[i][0];
		return canonicalVote;
	}
	
	
	/**
	 * To provide an uniform support for the canonical vote (including the MP1 canonical vote)
	 * this method puts the getCanonicalVote() result elements inside an individual 
	 * ElGamalEncryption array. 
	 * 
	 * This method must be overwritten in the MP1VoteAndReceipt class.
	 * 
	 * @return the canonical candidate votes as an array of ElGamalEncryptions. 
	 */
	public ElGamalEncryption[][] getCanonicalVoteElementsAsArray(IMPParameters param) {
		ElGamalEncryption[] canonicalVote = getCanonicalVote(param);
		ElGamalEncryption[][] asArray = new ElGamalEncryption[canonicalVote.length][];
		for(int i=0; i<canonicalVote.length; i++)
			asArray[i] = new ElGamalEncryption[]{canonicalVote[i]};
		return asArray;
	}
	
	
	/**
	 * Verify if the canonical vote validity using the CGS97 technique.
	 * 
	 * This method uses the following encoding:
	 * yes vote = param.getExponentialMessageGenerator()^1 - the Z*p q order subgroup element that represents a yes vote.
	 * no vote = param.getExponentialMessageGenerator()^-1 - the Z*p q order subgroup element that represents a no vote
	 * 
	 * @param param the MarkPledge parameters used in the vote encryption. 
	 * @param md MessageDigest object to compute the CGS97 challenge
	 * @return true if all CGS97 proofs of this object validate the canonical vote. Returns false otherwise.
	 */
	public boolean verifyCanonicalVote(IMPParameters param, MessageDigest md)
	{
		ElGamalEncryption[] canonicalVote = this.getCanonicalVote(param);
		CGS97BallotValidity[] canonicalVoteProofs = this.validityProofs.getCanonicalVoteCGS97Proof();
		return MPUtil.verifyCanonicalVote(canonicalVote, canonicalVoteProofs, param.getMP_G(),
				param.getMP_GInv(), param.getPublicKey(), md);
	}
	
	
	/**
	 * Verify the homomorphic canonical vote sum.
	 * This method uses the following encoding 
	 * for yes votes and no votes:
	 * yes vote = param.getExponentialMessageGenerator()^1 - the Z*p q order subgroup element that represents a yes vote.
	 * no vote = param.getExponentialMessageGenerator()^-1 - the Z*p q order subgroup element that represents a no vote
	 * 
	 * @param param the MarkPledge parameters used in the vote encryption
	 * @param numberOfSelectedCandidates number of selected candidates in the vote
	 * @return true if the homomorphic canonical vote sum correspond to numberOfSelectedCandidates yes votes. 
	 */
	public boolean verifyVoteSum(IMPParameters param, int numberOfSelectedCandidates)
	{
		BigInteger sumProof = this.validityProofs.getVoteSumProof();
		return MPUtil.verifyVoteSum(this.getCanonicalVote(param), sumProof, param.getMP_G(),
				param.getMP_GInv(), numberOfSelectedCandidates, param.getPublicKey());
	}
	
	/**
	 * Verify the vote receipt, the canonical vote construction and the vote homomorphic sum.
	 * IMPORTANT: This method uses the MPUtil.DEFAULT_HASH_FUNCTION in the canonical vote validation. 
	 * 
	 * @param param the MarkPledge parameters used in the vote encryption
	 * @param nSelectedCandidates the number of selected candidates in the vote.
	 * @param md MessageDigest object instantiated with the digest algorithm used in the receipt and proofs construction.
	 * @return true if all three verification are successful.
	 */
	public boolean verifyAll(IMPParameters param, int nSelectedCandidates, MessageDigest md)
	{
		return verifyReceipt(param, md) && verifyCanonicalVote(param, md) && verifyVoteSum(param, nSelectedCandidates);
	}
	
	/**
	 * Method that implement the receipt verification algorithm. 
	 * This method must be overwritten for concrete implementations (MP1, MP2 and MP3)
	 */
	public abstract boolean verifyReceipt(IMPParameters param, MessageDigest md);

}
