package gsd.inescid.markpledge3;

import gsd.inescid.crypto.util.Base64;
import gsd.inescid.crypto.util.CryptoUtil;
import gsd.inescid.crypto.ElGamalPublicKey;
import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.crypto.ElGamalVerifiableEncryption;
import java.util.Random;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidParameterException;

/**
 * 
 * @author Rui
 *
 * This class implements the ballot validity proof described in 
 * CGS97 (A Secure and Optimally Efficient Multi-Authority Election Scheme)
 * 
 * It implements the non interactive version using a hash function to 
 * generate a random challenge (Fiat-Shamir heuristic).
 */

public class CGS97BallotValidity {

	public static final String DEFAULT_HASH_FUNCTION = "SHA-1";

	//Validity proof data
	public final BigInteger A1;
	public final BigInteger A2;
	public final BigInteger B1;
	public final BigInteger B2;
	public final BigInteger C;
	public final BigInteger D1;
	public final BigInteger D2;
	public final BigInteger R1;
	public final BigInteger R2;

	// XML TAGS
	public static final String XML_TAG = "CGS97BallotValidity";
	public static final String XML_A1_TAG = "A1";
	public static final String XML_A2_TAG = "A2";
	public static final String XML_B1_TAG = "B1";
	public static final String XML_B2_TAG = "B2";
	public static final String XML_D1_TAG = "D1";
	public static final String XML_D2_TAG = "D2";
	public static final String XML_R1_TAG = "R1";
	public static final String XML_R2_TAG = "R2";
	public static final String XML_C_TAG = "C";

	public String toXML()
	{
		StringBuilder xml = new StringBuilder();
		xml.append(xml + "<" + XML_TAG + ">\n");
		xml.append("<" + XML_A1_TAG + ">" + Base64.encode(this.A1.toByteArray()) + "</" + XML_A1_TAG + ">\n");
		xml.append("<" + XML_A2_TAG + ">" + Base64.encode(this.A2.toByteArray()) + "</" + XML_A2_TAG + ">\n");
		xml.append("<" + XML_B1_TAG + ">" + Base64.encode(this.B1.toByteArray()) + "</" + XML_B1_TAG + ">\n");
		xml.append("<" + XML_B2_TAG + ">" + Base64.encode(this.B2.toByteArray()) + "</" + XML_B2_TAG + ">\n");
		xml.append("<" + XML_D1_TAG + ">" + Base64.encode(this.D1.toByteArray()) + "</" + XML_D1_TAG + ">\n");
		xml.append("<" + XML_D2_TAG + ">" + Base64.encode(this.D2.toByteArray()) + "</" + XML_D2_TAG + ">\n");
		xml.append("<" + XML_R1_TAG + ">" + Base64.encode(this.R1.toByteArray()) + "</" + XML_R1_TAG + ">\n");
		xml.append("<" + XML_R2_TAG + ">" + Base64.encode(this.R2.toByteArray()) + "</" + XML_R2_TAG + ">\n");
		xml.append("<" + XML_C_TAG + ">" + Base64.encode(this.C.toByteArray()) + "</" + XML_C_TAG + ">\n");
		xml.append(xml + "</" + XML_TAG + ">\n");
		return xml.toString();
	}

	public String toString()
	{
		StringBuilder s = new StringBuilder();
		s.append("A1: " + this.A1.toString(16).toUpperCase() + "\n");
		s.append("A2: " + this.A2.toString(16).toUpperCase() + "\n");
		s.append("B1: " + this.B1.toString(16).toUpperCase() + "\n");
		s.append("B2: " + this.B2.toString(16).toUpperCase() + "\n");
		s.append("D1: " + this.D1.toString(16).toUpperCase() + "\n");
		s.append("D2: " + this.D2.toString(16).toUpperCase() + "\n");
		s.append("R1: " + this.R1.toString(16).toUpperCase() + "\n");
		s.append("R2: " + this.R2.toString(16).toUpperCase() + "\n");
		s.append("C : " + this.C.toString(16).toUpperCase() + "\n");
		return s.toString();
	}

	
	public CGS97BallotValidity(BigInteger a1, BigInteger a2, BigInteger b1, BigInteger b2, 
			BigInteger r1, BigInteger r2, BigInteger d1, BigInteger d2, BigInteger c){
		this.A1 = a1;
		this.A2 = a2;
		this.B1 = b1;
		this.B2 = b2;
		this.R1 = r1;
		this.R2 = r2;
		this.D1 = d1;
		this.D2 = d2;
		this.C = c;
	}


	/**
	 * Create the validity proof data for the received ballot/vote encryption
	 *  
	 * @param ballotType ballot/vote type: true=>YESvote, false=>NOvote
	 * @param ballotEncryption ballot/vote encryption
	 * @param kpub public key used in the vote encryption
	 * @param m value encrypted: m=G^v and v=1 (YESvote) or v=-1 (NOvote)
	 * @param random source data
	 * @param hashFunction to use in the Fiat-Shamir heuristic
	 * 
	 * @throws NoSuchAlgorithmException if the hashFunction specified is not supported
	 */
	public CGS97BallotValidity(Boolean ballotType, ElGamalVerifiableEncryption ballotEncryption, 
			ElGamalPublicKey kpub, BigInteger m, Random random, String hashFunction) throws NoSuchAlgorithmException
			{
		if(random == null);
		random = new SecureRandom();
		if(hashFunction == null)
			hashFunction = DEFAULT_HASH_FUNCTION;

		MessageDigest md = MessageDigest.getInstance(hashFunction);

		//ElGamal encryption of the ballot/vote 
		BigInteger alpha = ballotEncryption.ENCRYPTION_FACTOR;
		BigInteger x = ballotEncryption.MESSAGE_ENCRYPTION.X; //g^alpha
		BigInteger y = ballotEncryption.MESSAGE_ENCRYPTION.Y; //h^alpha.G^v  with v=1 (YESvote) or v=-1 (NOvote)

		BigInteger w = CryptoUtil.generateRandomNumber(kpub.q, random);

		//create validity proof data
		if(ballotType) //YESvote (v=1)
		{
			//init validity proof data
			this.R1 = CryptoUtil.generateRandomNumber(kpub.q, random);
			this.D1 = CryptoUtil.generateRandomNumber(kpub.q, random);
			this.A1 = ((kpub.g.modPow(this.R1, kpub.p)).multiply(x.modPow(this.D1, kpub.p))).mod(kpub.p);
			this.B1 = ((kpub.h.modPow(this.R1, kpub.p)).multiply(
					((y.multiply(m)).mod(kpub.p)).modPow(this.D1, kpub.p))).mod(kpub.p);
			this.A2 = kpub.g.modPow(w, kpub.p);
			this.B2 = kpub.h.modPow(w, kpub.p);	

			//create challenge using the Fiat-Shamir heuristic
			byte[] digest = getCFirstBytes(md, x, y, this.A1, this.A2, this.B1, this.B2, kpub.p);
			this.C = new BigInteger(1, fillByteArrayByMultipleHash(digest, md, kpub.q));

			//complete validity proof data
			this.D2 = (this.C.subtract(this.D1)).mod(kpub.q);
			this.R2 = (w.subtract((alpha.multiply(this.D2)).mod(kpub.q))).mod(kpub.q);

		} 
		else //NOvote (v=-1)
		{
			//init validity proof data
			this.R2 = CryptoUtil.generateRandomNumber(kpub.q, random);
			this.D2 = CryptoUtil.generateRandomNumber(kpub.q, random);
			this.A1 = kpub.g.modPow(w, kpub.p);
			this.B1 = kpub.h.modPow(w, kpub.p);	
			this.A2 = ((kpub.g.modPow(this.R2, kpub.p)).multiply(x.modPow(this.D2, kpub.p))).mod(kpub.p);
			this.B2 = ((kpub.h.modPow(this.R2, kpub.p)).multiply(
					((y.multiply(m)).mod(kpub.p)).modPow(this.D2, kpub.p))).mod(kpub.p);

			//create challenge using the Fiat-Shamir heuristic
			byte[] digest = getCFirstBytes(md, x, y, this.A1, this.A2, this.B1, this.B2, kpub.p);
			this.C = new BigInteger(1, fillByteArrayByMultipleHash(digest, md, kpub.q));

			//complete validity proof data
			this.D1 = (this.C.subtract(this.D2)).mod(kpub.q);
			this.R1 = (w.subtract((alpha.multiply(this.D1)).mod(kpub.q))).mod(kpub.q);

		}
			}


	private static byte[] getCFirstBytes(MessageDigest digest, BigInteger x, BigInteger y, 
			BigInteger a1, BigInteger a2, BigInteger b1, BigInteger b2, BigInteger p)
	{
		int pLength = p.bitLength();
		pLength = pLength/8 + ((pLength%8 == 0)? 0 : 1);
		digest.reset();
		digest.update(CryptoUtil.copyLastBytesOf(x.toByteArray(), pLength));
		digest.update(CryptoUtil.copyLastBytesOf(y.toByteArray(), pLength));
		digest.update(CryptoUtil.copyLastBytesOf(a1.toByteArray(), pLength));
		digest.update(CryptoUtil.copyLastBytesOf(a2.toByteArray(), pLength));
		digest.update(CryptoUtil.copyLastBytesOf(b1.toByteArray(), pLength));
		digest.update(CryptoUtil.copyLastBytesOf(b2.toByteArray(), pLength));
		byte[] r = digest.digest();
		//System.out.println((new BigInteger(1,r)).toString(16));
		return r;
	}


	/**
	 * This method verifies the validity of a ballot/vote accordingly to the CGS97 validation algorithm 
	 * 
	 * @param ballot - the ballot/vote to verify
	 * @param validity - the validity proof data
	 * @param kpub - the public key used in the ballot/vote encryption
	 * @param m - message representing a YESvote (G^1 in CGS97)
	 * @param mInv - message representing a NOvote (G^-1 in CGS97)
	 * @param hashFunction name of the hash function used in the CGS97 c parameter generation process
	 * 
	 * @return true if the verification process succeeds and false otherwise.
	 */
	public static boolean verifyBallotValidity(ElGamalEncryption ballot, CGS97BallotValidity validity, ElGamalPublicKey kpub, 
			BigInteger m, BigInteger mInv, MessageDigest md)
			{
		//recustruct c value
		byte[] digest = getCFirstBytes(md, ballot.X, ballot.Y, validity.A1, validity.A2, validity.B1, validity.B2, kpub.p);
		byte[] checkC = fillByteArrayByMultipleHash(digest, md, kpub.q);
		//byte[] checkC = digest;
		//System.out.println((new BigInteger(1,checkC)).toString(16));
		
		/*
		System.out.println("new1 C: " + new BigInteger(1,digest).toString(16));
		System.out.println("new2 C: " + new BigInteger(1,checkC).toString(16));
		System.out.println("    d1: " + validity.D1.toString(16));
		System.out.println("    d2: " + validity.D2.toString(16));
		System.out.println("   mod: " + kpub.q.toString(16));
		System.out.println(" d1+d2: " + ((validity.D1.add(validity.D2)).mod(kpub.q)).toString(16));
		 */
		/*
		System.out.println("ballotX: " + ballot.X.toString(16));
		System.out.println("ballotY: " + ballot.Y.toString(16));
		
		BigInteger a = kpub.h.modPow(validity.R2,kpub.p);
		System.out.println("Step1: " + a.toString(16));
		BigInteger b = ballot.Y.multiply(mInv).mod(kpub.p);
		System.out.println("Step2: " + b.toString(16));
		BigInteger c = b.modPow(validity.D2, kpub.p);
		System.out.println("Step3: " + c.toString(16));
		BigInteger d = a.multiply(c).mod(kpub.p);
		System.out.println("Step4: " + d.toString(16));
		*/
		
		
		if(validity.C.equals(new BigInteger(1,checkC)) &&
				validity.C.equals((validity.D1.add(validity.D2)).mod(kpub.q)) &&
				validity.A1.equals(((kpub.g.modPow(validity.R1,kpub.p)).multiply((ballot.X.modPow(validity.D1, kpub.p)))).mod(kpub.p)) &&
				validity.A2.equals(((kpub.g.modPow(validity.R2,kpub.p)).multiply((ballot.X.modPow(validity.D2, kpub.p)))).mod(kpub.p)) &&
				validity.B1.equals(((kpub.h.modPow(validity.R1,kpub.p)).multiply(
						(((ballot.Y.multiply(m)).mod(kpub.p)).modPow(validity.D1, kpub.p)))).mod(kpub.p)) &&
				validity.B2.equals(((kpub.h.modPow(validity.R2,kpub.p)).multiply(
								(((ballot.Y.multiply(mInv)).mod(kpub.p)).modPow(validity.D2, kpub.p)))).mod(kpub.p)))
		{
			return true;
		}
		else
		{
			return false;
		}
			}


	/**
	 * This method return a pseudo-random value in Z_q by making multiple hashes of the originalData
	 * 
	 * @param originalData base input data to the hash function 
	 * @param md Message digest object to use
	 * @param q limit value
	 * 
	 * @return pseudo-random value in Z_q = r_0 || r_1 || r_2 ...
	 * 				   						r_0 = originalData
	 * 				   						r_i = digest(r_(i-1))
	 * 
	 * @throws InvalidParameterException when a parameter is null 
	 */
	public static final byte[] fillByteArrayByMultipleHash(byte[] originalData, MessageDigest md, BigInteger q)
	{
		//Parameter validation
		if(originalData == null)
			throw new InvalidParameterException("originalData parameter is null");
		if(q == null)
			throw new InvalidParameterException("arrayToFill parameter is null");

		//Algorithm
		md.reset(); 
		int index = 0, hashIndex=0;
		int qLength = q.bitLength();
		byte[] result = new byte[qLength/8 + ((qLength%8 == 0)? 0 : 1)];

		byte[] lastHash = originalData;

		//Fill with initial data fill array
		while(index < result.length && hashIndex < lastHash.length)
			result[index++] = lastHash[hashIndex++];		

		while(index < result.length)
		{		
			md.update(lastHash);
			lastHash = md.digest();

			//fill array
			hashIndex=0;
			while(index < result.length && hashIndex < lastHash.length)
				result[index++] = lastHash[hashIndex++];		
		}

		//adjust result to Z_q by shifting the high order byte bits of the result until a value less than q is achieved
		int br = result[0];
		br &= 0x00FF; //eliminate negative result from the 2's-complement representation
		byte[] qArray= q.toByteArray();
		int bq = qArray[0] != 0 ? qArray[0] : qArray[1]; //removes a zero byte that may appear because of the 2's-complement representation  
		bq &= 0x00FF; //eliminate negative result from the 2's-complement representation
		while (br >= bq)
			br >>>= 1;

		result[0] = (byte)br;
		return result;
	}
}
