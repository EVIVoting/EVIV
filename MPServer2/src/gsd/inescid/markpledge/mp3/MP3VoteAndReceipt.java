package gsd.inescid.markpledge.mp3;

import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.crypto.ElGamalPublicKey;
import gsd.inescid.crypto.ElGamalVerifiableEncryption;
import gsd.inescid.markpledge.MPAbstractVoteAndReceipt;
import gsd.inescid.markpledge.interfaces.IMPEncryptedVote;
import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.interfaces.IMPReceipt;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;

import java.math.BigInteger;
import java.security.MessageDigest;

/**
 * This class contains the MP3 specific verifications algorithms implementation.
 * @author Rui
 *
 */
public class MP3VoteAndReceipt extends MPAbstractVoteAndReceipt {

	/**
	 * Default constructor
	 */
	public MP3VoteAndReceipt(){};
	
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
	public MP3VoteAndReceipt(IMPEncryptedVote vote, IMPReceipt receipt, IMPValidityProof voteValidityProof) {
		super(vote, receipt, voteValidityProof);
	}

	
	
	
	
	

	public boolean verifyReceipt(IMPParameters param, MessageDigest md) {
		md.reset();
		ElGamalPublicKey kpub = param.getPublicKey();
		ElGamalEncryption[][] voteEnc = this.voteEnc.getEncryptedVote();
		BigInteger challenge = this.receipt.getChallenge();
		BigInteger[] verificationCodes = this.receipt.getVerificationCodes();
		BigInteger[][] validityFactors = this.receipt.getReceiptValidity();
		
		BigInteger verificationMessage = param.getMP_G().modPow(challenge, kpub.p);
		
		for(int i=0; i<voteEnc.length;i++)
		{
			// create verifiable challenge encryption
			BigInteger cvX = voteEnc[i][0].X;
			BigInteger cvY = voteEnc[i][0].Y;
			BigInteger commitX = voteEnc[i][1].X;
			BigInteger commitY = voteEnc[i][1].Y;
			
			BigInteger distance = challenge.subtract(verificationCodes[i]).mod(kpub.q);

			BigInteger newX = (cvX.modPow(distance, kpub.p).multiply(commitX)).mod(kpub.p);
			BigInteger newY = (cvY.modPow(distance, kpub.p).multiply(commitY)).mod(kpub.p);
			
			ElGamalVerifiableEncryption chalEnc = new ElGamalVerifiableEncryption(new ElGamalEncryption(newX, newY),
					validityFactors[i][0]);
				
			// verify the challenge encryption
			if(!kpub.verifyQOrderMessageEncryption(verificationMessage, chalEnc))
			{
				return false;
			}
		}
		return true;
	}
}
