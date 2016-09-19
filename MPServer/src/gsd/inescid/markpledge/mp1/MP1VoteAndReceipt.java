package gsd.inescid.markpledge.mp1;

import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.crypto.ElGamalPublicKey;
import gsd.inescid.crypto.ElGamalVerifiableEncryption;
import gsd.inescid.markpledge.MPAbstractVoteAndReceipt;
import gsd.inescid.markpledge.interfaces.IMPEncryptedVote;
import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.interfaces.IMPReceipt;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;
import gsd.inescid.markpledge.mp2.MP2Util;

import java.math.BigInteger;
import java.security.MessageDigest;

public class MP1VoteAndReceipt extends MPAbstractVoteAndReceipt {

	/**
	 * Default constructor
	 */
	public MP1VoteAndReceipt(){};
	
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
	public MP1VoteAndReceipt(IMPEncryptedVote vote, IMPReceipt receipt, IMPValidityProof voteValidityProof) {
		super(vote, receipt, voteValidityProof);
	}
	
	@Override
	public boolean verifyReceipt(IMPParameters param, MessageDigest md) {
		int alpha = param.getAlpha();
		ElGamalPublicKey kpub = param.getPublicKey();
		BigInteger oneEncoding = param.getMP_G();
		BigInteger zeroEncoding = param.getMP_GInv();
		
		ElGamalEncryption[][] voteEnc = this.voteEnc.getEncryptedVote();
		ElGamalEncryption revealedBMPElement;
		
		ElGamalVerifiableEncryption toVerify;
		
		BigInteger[] vcodes = this.receipt.getVerificationCodes();
		BigInteger[][] validityFactors = this.receipt.getReceiptValidity();
		BigInteger chal = this.receipt.getChallenge();
		BigInteger vcode;
		
		boolean verify;
		
		for(int i=0; i<voteEnc.length; i++)
		{
			vcode = vcodes[i];
			for(int k=alpha-1, iBMP=0; k>=0; k--, iBMP++ )
			{
				if(chal.testBit(k))// open right BMP element
					revealedBMPElement = voteEnc[i][iBMP*2 + 1];
				else //open left BMP element
					revealedBMPElement = voteEnc[i][iBMP*2];
				
				toVerify = new ElGamalVerifiableEncryption(revealedBMPElement,validityFactors[i][iBMP]);
				
				if(vcode.testBit(k))// verify one encryption
					verify = kpub.verifyQOrderMessageEncryption(oneEncoding, toVerify);
				else //verify zero encryption
					verify = kpub.verifyQOrderMessageEncryption(zeroEncoding, toVerify);
											
				if(!verify)
				{	
					System.out.println("Not verified bit " + k + " : " + verify);
					return false;
				}
			}
		}
		
		return true;
	}

	
	
	/**
	 * This method returns the first ElGamalEncryption of MP1 canonical vote.
	 * It DOES NOT verify that all encryptions (within each candidate encryption)
	 * of MP1 canonical vote are equal.
	 * Use this method only for tests.
	 * 
	 * @param param the MarkPledge encryption parameters
	 * @return the first ElGamalEncryption of MP1 canonical vote.
	 */
	@Override
	public ElGamalEncryption[] getCanonicalVote(IMPParameters param)
	{
		ElGamalEncryption[][] canonicalVote =getCanonicalVoteElementsAsArray(param);
		ElGamalEncryption[] result = new ElGamalEncryption[canonicalVote.length];
		for(int i=0; i<result.length; i++)
			result[i] = canonicalVote[i][0];
		return result;
	}
	
	
	/**
	 * Transform the BMP encryptions into a canonical vote encryption.
	 * @param param the MarkPledge encryption parameters 
	 * @return the canonical candidate votes as an array of ElGamalEncryptions. 
	 */
	public ElGamalEncryption[][] getCanonicalVoteElementsAsArray(IMPParameters param) {
		int alpha = param.getAlpha();
		
		BigInteger p = param.getP();
		BigInteger minusOne = new BigInteger("-1");
		ElGamalEncryption[][] voteEnc = this.voteEnc.getEncryptedVote();
		ElGamalEncryption[][] canonicalVote = new ElGamalEncryption[voteEnc.length][alpha];
		ElGamalEncryption encryptedBMPElement;
		BigInteger[] vcodes = this.receipt.getVerificationCodes();
		BigInteger chal = this.receipt.getChallenge();
		
		BigInteger vcode;
		
		for(int i=0; i<canonicalVote.length; i++)
		{
			vcode = vcodes[i];
			
			for(int k=alpha-1, iBMP=0; k>=0; k--, iBMP++ )
			{
				if(chal.testBit(k))// use the left BMP element
					encryptedBMPElement = voteEnc[i][iBMP*2];
				else //use the right BMP element
					encryptedBMPElement = voteEnc[i][iBMP*2 + 1];
				
				if(!vcode.testBit(k))//invert the encryption of the not revealed BMP element
				{
					encryptedBMPElement = MP2Util.multiplyByClearTextValue(encryptedBMPElement, minusOne, p);
				}
				canonicalVote[i][iBMP] = encryptedBMPElement;
			}
		}
		return canonicalVote;
	}
	
	
	/**
	 * This MP1 implementation DOES NOT support the canonical vote validity using the CGS97 technique. 
	 * @throws UnsupportedOperationException
	 */
	public boolean verifyCanonicalVote(IMPParameters param, MessageDigest md)
	{
		throw new UnsupportedOperationException();
	}
	
	
	/**
	 * This MP1 implementation DOES NOT support homomorphic vote aggregation canonical because of the
	 * lack of the vote validity proof.
	 * Therefore this method is not implemented. 
	 * @throws UnsupportedOperationException
	 */
	public boolean verifyVoteSum(IMPParameters param, int numberOfSelectedCandidates)
	{
		throw new UnsupportedOperationException();
	}
}
