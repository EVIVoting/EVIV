package gsd.inescid.markpledge.mp1a;

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

public class MP1AVoteAndReceipt extends MPAbstractVoteAndReceipt {

	/**
	 * Default constructor
	 */
	public MP1AVoteAndReceipt(){};
	
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
	public MP1AVoteAndReceipt(IMPEncryptedVote vote, IMPReceipt receipt, IMPValidityProof voteValidityProof) {
		super(vote, receipt, voteValidityProof);
	}
	
	@Override
	public boolean verifyReceipt(IMPParameters param, MessageDigest md) {
		int alpha = param.getAlpha();
		ElGamalPublicKey kpub = param.getPublicKey();
		BigInteger mpG = param.getMP_G();
		BigInteger oneEncoding = mpG;
		BigInteger zeroEncoding = param.getMP_GInv();
		BigInteger p = param.getP();
		
		ElGamalEncryption[][] voteEnc = this.voteEnc.getEncryptedVote();
		ElGamalEncryption revealedBMPElement;
		ElGamalEncryption unrevealedBMPElement;
		
		ElGamalVerifiableEncryption toVerify;
		
		BigInteger[] vcodes = this.receipt.getVerificationCodes();
		BigInteger[][] validityFactors = this.receipt.getReceiptValidity();
		BigInteger chal = this.receipt.getChallenge();
		BigInteger vcode;
		
		boolean verify;
		
		for(int i=0; i<voteEnc.length; i++)
		{
			vcode = vcodes[i];
			
			for(int k=alpha-1, iBMP=0; k>=0; k--, iBMP++) 
			{
				if(chal.testBit(k))// open right BMP element
				{
					revealedBMPElement = voteEnc[i][1+ iBMP*2 + 1]; //first ElGamal encryption is the canonical vote
					unrevealedBMPElement =  voteEnc[i][1+ iBMP*2]; //first ElGamal encryption is the canonical vote
				}
				else //open left BMP element
				{
					revealedBMPElement = voteEnc[i][1+ iBMP*2]; //first ElGamal encryption is the canonical vote
					unrevealedBMPElement =  voteEnc[i][1+ iBMP*2 + 1]; //first ElGamal encryption is the canonical vote
				}
				
				//the first alpha factors are the conformity factors
				toVerify = new ElGamalVerifiableEncryption(revealedBMPElement,validityFactors[i][alpha + iBMP]);
				
				if(vcode.testBit(k)) // verify one encryption
					verify = kpub.verifyQOrderMessageEncryption(oneEncoding, toVerify);
				else//verify zero encryption
					verify = kpub.verifyQOrderMessageEncryption(zeroEncoding, toVerify);
				
				if(!verify)
				{	
					System.out.println("Not verified bit " + k + " : " + verify);
					return false;
				}
				
				//verify conformity with canonical vote
				if(vcode.testBit(k))////verify if division encrypts g^1
				{
					//unrevealedBMPElement = voteEnc[i][0].divide(unrevealedBMPElement, p);
					unrevealedBMPElement = MP2Util.multiplyByClearTextValue(unrevealedBMPElement, new BigInteger("-1"), p);
					unrevealedBMPElement = unrevealedBMPElement.multiply(voteEnc[i][0], p);
					toVerify = new ElGamalVerifiableEncryption(unrevealedBMPElement, validityFactors[i][iBMP]);
					verify = kpub.verifyQOrderMessageEncryption(BigInteger.ONE, toVerify);
					if(!verify)
						System.out.println("Dverified bit " + k + " : " + verify);
				}
				else  //verify if multiplication encrypts g^0
				{
					unrevealedBMPElement = unrevealedBMPElement.multiply(voteEnc[i][0], p);
					toVerify = new ElGamalVerifiableEncryption(unrevealedBMPElement, validityFactors[i][iBMP]);
					verify = kpub.verifyQOrderMessageEncryption(BigInteger.ONE, toVerify);
					if(!verify)
						System.out.println("Mverified bit " + k + " : " + verify);
				}
				
				if(!verify)
				{	
					System.out.println("Conformity not verified bit " + k + " : " + verify);
					return false;
				}
			}
		}
		return true;
	}

}
