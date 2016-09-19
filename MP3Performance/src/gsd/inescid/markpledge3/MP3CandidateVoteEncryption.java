package gsd.inescid.markpledge3;

import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.crypto.ElGamalVerifiableEncryption;
import gsd.inescid.crypto.util.Base64;

import java.math.BigInteger;

public class MP3CandidateVoteEncryption {
	public final ElGamalEncryption BIT_ENCRYPTION;
	public final CGS97BallotValidity BIT_ENCRYPTION_VALIDITY;
	public final ElGamalEncryption COMMIT_ENCRYPTION;
	public final BigInteger VERIFICATION_VALUE;
	public final BigInteger VERIFICATION_ENCRYPTION_FACTOR;
	
	public MP3CandidateVoteEncryption(ElGamalEncryption be, CGS97BallotValidity validity, ElGamalEncryption ccode,
											 BigInteger verificationValue, BigInteger encryptionFactor)
	{
		this.BIT_ENCRYPTION = be;
		this.BIT_ENCRYPTION_VALIDITY = validity;
		this.COMMIT_ENCRYPTION = ccode;
		this.VERIFICATION_VALUE = verificationValue;
		this.VERIFICATION_ENCRYPTION_FACTOR = encryptionFactor;
	}
	
	// XML TAGS
	public static final String XML_TAG = "CGS97BallotValidity";
	public static final String XML_BE_TAG = "BE";
	public static final String XML_COMMIT_TAG = "COMMIT";
	public static final String XML_VERIFICATION_VALUE_TAG = "VerificationValue";
	public static final String XML_VERIFICATION_ENCRYPTION_FACTOR_TAG = "VerificationEncryptionFactor";
	
	public String toXML()
	{
		StringBuilder xml = new StringBuilder();
		xml.append(xml + "<" + XML_TAG + ">\n");
		xml.append(this.BIT_ENCRYPTION.toXML());
		xml.append(this.BIT_ENCRYPTION_VALIDITY.toXML());
		xml.append(this.COMMIT_ENCRYPTION.toXML());
		xml.append("<" + XML_VERIFICATION_VALUE_TAG + ">" + Base64.encode(this.VERIFICATION_VALUE.toByteArray()) + "</" + XML_VERIFICATION_VALUE_TAG + ">\n");
		xml.append("<" + XML_VERIFICATION_ENCRYPTION_FACTOR_TAG + ">" + Base64.encode(this.VERIFICATION_ENCRYPTION_FACTOR.toByteArray()) + "</" + XML_VERIFICATION_ENCRYPTION_FACTOR_TAG + ">\n");
		xml.append(xml + "</" + XML_TAG + ">\n");
		return xml.toString();
	}
		
	/**
	 * This method builds a verifiable ElGamal encryption for this 
	 * candidate vote encryption and the given challenge. 
	 * The verification will only work if the chal value is the same that 
	 * was used in the invocation of the method "MP3PreparedCandidateVote".getCandidateEncryption 
	 * which has originated this MP3CandidateVoteEncryption.
	 *  
	 * @param chal challenge to which the verifiable construction must be build
	 * @param p the modulus of the encryption key
	 * @param q the order of the message/challenge space
	 * @return the verifiable ElGamal encryption
	 */
	public ElGamalVerifiableEncryption getVerifiableEncryption(BigInteger chal, BigInteger p, BigInteger q)
	{
		BigInteger cvX = this.BIT_ENCRYPTION.X;
		BigInteger cvY = this.BIT_ENCRYPTION.Y;
		BigInteger commitX = this.COMMIT_ENCRYPTION.X;
		BigInteger commitY = this.COMMIT_ENCRYPTION.Y;
		
		BigInteger distance = chal.subtract(this.VERIFICATION_VALUE).mod(q);

		BigInteger newX = (cvX.modPow(distance, p).multiply(commitX)).mod(p);
		BigInteger newY = (cvY.modPow(distance, p).multiply(commitY)).mod(p);
		
		return new ElGamalVerifiableEncryption(new ElGamalEncryption(newX, newY), this.VERIFICATION_ENCRYPTION_FACTOR);
	}
	
	public String toString()
	{
		String s = "\nMarkPledge3 candidate vote encryption"
				 + "\nCandidate vote enc:\n" + this.BIT_ENCRYPTION
				 + "\n------------------------------------------------"
				 + "\nCommitment encrypt:\n" + this.COMMIT_ENCRYPTION
				 + "\n------------------------------------------------"
				 + "\nVerification value = " + this.VERIFICATION_VALUE
				 + "\nEncryption verification factor = " + this.VERIFICATION_ENCRYPTION_FACTOR
				 + "\n------------------------------------------------\n";
		return s;
	}
}
