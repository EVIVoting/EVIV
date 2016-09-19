package gsd.inescid.markpledge.mp2;

import java.math.BigInteger;
import java.security.MessageDigest;

import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.crypto.ElGamalPublicKey;
import gsd.inescid.crypto.ElGamalVerifiableEncryption;
import gsd.inescid.markpledge.MPAbstractVoteAndReceipt;
import gsd.inescid.markpledge.interfaces.IMPEncryptedVote;
import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.interfaces.IMPReceipt;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;
import gsd.inescid.markpledge.mp2.interfaces.IMP2Parameters;
import gsd.inescid.markpledge2.MP2Util;

public class MP2VoteAndReceipt extends MPAbstractVoteAndReceipt {

	/**
	 * Default constructor
	 */
	public MP2VoteAndReceipt(){};
	
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
	public MP2VoteAndReceipt(IMPEncryptedVote vote, IMPReceipt receipt, IMPValidityProof voteValidityProof) {
		super(vote, receipt, voteValidityProof);
	}
	
	@Override
	public boolean verifyReceipt(IMPParameters param, MessageDigest md) 
	{
		IMP2Parameters mp2Param = (IMP2Parameters) param;
		BigInteger[] vCodes = this.receipt.getVerificationCodes(); 
		ElGamalEncryption[][] voteEnc = this.voteEnc.getEncryptedVote();
		BigInteger[][] validityFactor = this.receipt.getReceiptValidity();
		BigInteger chal = this.receipt.getChallenge();
		BigInteger p = param.getP();
		BigInteger q = param.getQ();
		BigInteger mpG = param.getMP_G();
		BigInteger lambda = mp2Param.getLambda();
		ElGamalPublicKey kpub = param.getPublicKey();
		BigInteger zeroVectorIndex;
		BigInteger[] zeroVector;
		BigInteger[] chalVector;
	
		
		for(int i=0; i<vCodes.length; i++)
		{
					
			zeroVectorIndex = chal.subtract(vCodes[i]).mod(lambda);
			zeroVector = mp2Param.getZeroVector(zeroVectorIndex);
			chalVector = mp2Param.getTestVector(chal);

			/* vector subtraction */
			ElGamalEncryption[] subVector = MP2Util.vectorSubtraction(voteEnc[i], zeroVector, p, q, mpG);

			/* dot product with chal vector */
			ElGamalEncryption dotProduct = MP2Util.vectorDotProduct(subVector, chalVector, p);

			/*verify orthogonality */
			ElGamalVerifiableEncryption verifiableDotProduct = 
				new ElGamalVerifiableEncryption(dotProduct, validityFactor[i][0]);

			boolean verify = kpub.verifyQOrderMessageEncryption(BigInteger.ONE, verifiableDotProduct);
			if (!verify)
				return false;
		}
		return true;
	}

	@Override
	public ElGamalEncryption[] getCanonicalVote(IMPParameters param)
	{
		IMP2Parameters mp2Param = (IMP2Parameters) param;
		ElGamalEncryption[][] voteEnc = this.voteEnc.getEncryptedVote();
		BigInteger[] vCodes = this.receipt.getVerificationCodes();
		BigInteger[] oneVector;
		BigInteger[] zeroVector;
		BigInteger chal = this.receipt.getChallenge();
		BigInteger lambda = mp2Param.getLambda();
		BigInteger subVector[];
		BigInteger q = param.getPublicKey().q;
		BigInteger p = param.getPublicKey().p;
		BigInteger mpG = param.getMP_G();
		ElGamalEncryption[] canonicalVote = new ElGamalEncryption[voteEnc.length];
		BigInteger canonicalTransformationFactor;
		ElGamalEncryption[] subVectorEnc;
		final BigInteger TWO = new BigInteger("2"); 
		BigInteger aux;
		
		for(int i=0; i < voteEnc.length; i++)
		{
			oneVector = mp2Param.getOneVector(vCodes[i]);
			zeroVector = mp2Param.getZeroVector(chal.subtract(vCodes[i]).mod(lambda));
			subVector = MP2Util.vectorSubtraction(oneVector, zeroVector, q);
			subVectorEnc = MP2Util.vectorSubtraction(voteEnc[i], zeroVector, p, q, mpG);
			
			if(subVector[0].equals(BigInteger.ZERO))
			{
				canonicalTransformationFactor = subVector[1].modInverse(q);
				canonicalVote[i] = MP2Util.multiplyByClearTextValue(subVectorEnc[1], 
						canonicalTransformationFactor, p);
			} else {
				canonicalTransformationFactor = subVector[0].modInverse(q);
				canonicalVote[i] = MP2Util.multiplyByClearTextValue(subVectorEnc[0],
						canonicalTransformationFactor, p);
			}
			
			canonicalVote[i] = MP2Util.multiplyByClearTextValue(canonicalVote[i], TWO, p);
			aux = canonicalVote[i].Y.multiply(param.getMP_GInv());
			canonicalVote[i] = new ElGamalEncryption(canonicalVote[i].X, aux.mod(p));
			
		}
		return canonicalVote;
	}
}
