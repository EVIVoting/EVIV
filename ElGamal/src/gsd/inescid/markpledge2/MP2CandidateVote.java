package gsd.inescid.markpledge2;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.util.Random;

import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.crypto.ElGamalKeyFactory;
import gsd.inescid.crypto.ElGamalKeyPair;
import gsd.inescid.crypto.ElGamalKeyParameters;
import gsd.inescid.crypto.ElGamalPrivateKey;
import gsd.inescid.crypto.ElGamalPublicKey;
import gsd.inescid.crypto.ElGamalVerifiableEncryption;
import gsd.inescid.crypto.util.CryptoUtil;
import gsd.inescid.markpledge3.CGS97BallotValidity;
import gsd.inescid.math.algebra.matrix.MatrixUtil;

/**
 * MP2 candidate vote support class
 * 
 * @author Rui Joaquim
 *
 */
public class MP2CandidateVote {
	private static ElGamalPrivateKey kpri;
	private static final BigInteger FOUR = new BigInteger("4");
	
	public ElGamalVerifiableEncryption[] verifiableVectorEncryption; 
	public ElGamalEncryption[] vectorEncryption;
	public BigInteger[] vector;
	public BigInteger vectorIndex;
	public BigInteger verificationVectorIndex;
	public BigInteger verificationValue;
	public boolean isYesVote;
	public BigInteger chal;
	
	
	public static MP2CandidateVote getMP2CandidateVote(boolean yesVote, MP2Parameters param) throws InvalidAlgorithmParameterException
	{
		Random random = new SecureRandom();
		MP2CandidateVote cvote = new MP2CandidateVote();
		cvote.isYesVote = yesVote;
		cvote.vectorIndex = CryptoUtil.generateRandomNumber(param.LAMBDA, random);
		cvote.vector = cvote.isYesVote ? param.getYesVector(cvote.vectorIndex):
										 param.getNoVector(cvote.vectorIndex);
		cvote.verifiableVectorEncryption = new ElGamalVerifiableEncryption[2];
		cvote.verifiableVectorEncryption[0] = param.PUBLIC_KEY.exponentialVerifiableEncrypt(cvote.vector[0]);
		cvote.verifiableVectorEncryption[1] = param.PUBLIC_KEY.exponentialVerifiableEncrypt(cvote.vector[1]);
				
		return cvote;
	}
	
	public void createVerificationProof(BigInteger chal, MP2Parameters param)
	{
		if(this.isYesVote)
			this.verificationVectorIndex = this.vectorIndex;
		else 
			this.verificationVectorIndex = (chal.subtract(this.vectorIndex)).mod(param.LAMBDA);

		BigInteger[] chalVector = param.getTestVector(chal);
		BigInteger vFactorX = this.verifiableVectorEncryption[0].ENCRYPTION_FACTOR.multiply(chalVector[0]);
		BigInteger vFactorY = this.verifiableVectorEncryption[1].ENCRYPTION_FACTOR.multiply(chalVector[1]);
		
		this.verificationValue = vFactorX.add(vFactorY).mod(param.PUBLIC_KEY.q); 
		
	}
	
	public static boolean verifyVectorEncryption(MP2CandidateVote cvote, MP2Parameters param, 
			BigInteger chalVectorIndex, ElGamalEncryption[] canonicalVote) throws InvalidAlgorithmParameterException
			{
		ElGamalPublicKey kpub = param.PUBLIC_KEY;
		BigInteger zeroVectorIndex = (chalVectorIndex.subtract(cvote.verificationVectorIndex)).mod(param.LAMBDA);
		BigInteger[] zeroVector = param.getNoVector(zeroVectorIndex);
		BigInteger[] chalVector = param.getTestVector(chalVectorIndex);

		/* vector subtraction */
		ElGamalEncryption[] subVector = MP2Util.vectorSubtraction(cvote.getVectorEncryption(), zeroVector, kpub.p, kpub.q, kpub.g); 

		/* dot product with chal vector */
		ElGamalEncryption dotProduct = MP2Util.vectorDotProduct(subVector, chalVector, kpub.p);

		/*verify orthogonality */
		ElGamalVerifiableEncryption verifiableDotProduct = 
			new ElGamalVerifiableEncryption(dotProduct, cvote.verificationValue);

		boolean verify = kpub.verifyQOrderMessageEncryption(BigInteger.ONE, verifiableDotProduct);
		
		/* create canonical vote*/
		if(canonicalVote!=null && verify)
		{
			BigInteger[] oneVector = param.getYesVector(cvote.verificationVectorIndex);
			BigInteger sub[] = MP2Util.vectorSubtraction(oneVector, zeroVector, kpub.q);
			BigInteger v;
			if(sub[0].equals(BigInteger.ZERO))
			{
				v = sub[1].mod(kpub.q).modInverse(kpub.q);
				canonicalVote[0] = MP2Util.multiplyByClearTextValue(subVector[1], v, kpub.p);
			} else {
				v = sub[0].mod(kpub.q).modInverse(kpub.q);
				canonicalVote[0] = MP2Util.multiplyByClearTextValue(subVector[0], v, kpub.p);
			}
		}
		return verify;
	}
	
	public ElGamalEncryption[] getVectorEncryption()
	{
		if (this.vectorEncryption == null)
			this.vectorEncryption = new ElGamalEncryption[]{this.verifiableVectorEncryption[0].MESSAGE_ENCRYPTION, this.verifiableVectorEncryption[1].MESSAGE_ENCRYPTION};
		return this.vectorEncryption;
	}
		
	
}
