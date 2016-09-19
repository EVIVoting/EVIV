package gsd.inescid.crypto;

import gsd.inescid.crypto.util.Base64;
import gsd.inescid.crypto.util.CryptoUtil;

import java.math.BigInteger;
import java.util.Random;
import java.security.InvalidParameterException;
import java.security.SecureRandom;


/**
 * Class ElGamalPublicKey
 * @author Rui
 *
 */
public final class ElGamalPublicKey {
	public final BigInteger p; // a prime such that p = 2*k*q + 1
	public final BigInteger q; 
	public final BigInteger g; // generator of G_q, a q-order subgroup of Z*_p that defines the message space
	public final BigInteger h; // ElGamal public key h = g^x where x is the private key
	private Random random = null;
	
	// XML TAGS
	public static final String XML_TAG = "ElGamalPublicKey";
	public static final String XML_P_TAG = "P";
	public static final String XML_Q_TAG = "Q";
	public static final String XML_G_TAG = "G";
	public static final String XML_H_TAG = "H";
	
	public String toXML()
	{
		StringBuilder xml = new StringBuilder();
		xml.append("<" + XML_TAG + ">\n");
		xml.append("<" + XML_P_TAG + ">" + Base64.encode(this.p.toByteArray()) + "</" + XML_P_TAG + ">\n");
		xml.append("<" + XML_Q_TAG + ">" + Base64.encode(this.q.toByteArray()) + "</" + XML_Q_TAG + ">\n");
		xml.append("<" + XML_G_TAG + ">" + Base64.encode(this.g.toByteArray()) + "</" + XML_G_TAG + ">\n");
		xml.append("<" + XML_H_TAG + ">" + Base64.encode(this.h.toByteArray()) + "</" + XML_H_TAG + ">\n");
		xml.append("</" + XML_TAG + ">\n");
		return xml.toString();
	}
		
	
	public ElGamalPublicKey(ElGamalKeyParameters param, BigInteger h)
	{
		this.p = param.p;
		this.q = param.q;
		this.g = param.g;
		this.h = h;
	}
	
	/**
	 * Initializes the randomness source to use in the encryption
	 * @param r randomness source
	 */
	public void init(Random r)
	{
		this.random = r;
	}
	
	/**
	 * Encrypt message m in Z_q 
	 * 
	 * ***** USE ONLY IF p = 2q+1 *****
	 * 
	 * @param m message to encrypt
	 * @param rf random factor to use in the encryption
	 * @return the encrypted message
	 * @throws InvalidParameterException if m >= this.q or m < 0
	 */
	public final ElGamalEncryption encrypt(BigInteger m, BigInteger rf)
	{
		if (m.compareTo(this.q)>=0 || m.compareTo(BigInteger.ZERO)<0)
			throw new InvalidParameterException("Message to encrypt must be in Z_q");
		
		return baseEncryption(encodeMessage(m), rf);
	}
		
	/**
	 * Encrypt message m in Z_q 
	 * 
	 * ***** USE ONLY IF p = 2q+1 *****
	 * 
	 * It uses a random encryption factor in the range [1, q[.
	 * @param m message to encrypt
	 * @return the encrypted message
	 * @throws InvalidParameterException if m >= this.q or m < 0
	 */
	public final ElGamalEncryption encrypt(BigInteger m)
	{
		BigInteger rf = generateRandomFactor();
		return encrypt(encodeMessage(m), rf);
	}
		
	/**
	 * Encrypt message m in Z_q
	 * 
	 * ***** USE ONLY IF p = 2q+1 *****
	 * 
	 * It uses a random encryption factor in the range [1, q[.
	 * @param m message to encrypt
	 * @return the encrypted message and the random factor used
	 * @throws InvalidParameterException if m >= this.q or m < 0
	 */
	public final ElGamalVerifiableEncryption encryptVerifiable(BigInteger m)
	{
		// generate a random encryption factor in the range [1, q[. 
		BigInteger rf = generateRandomFactor();
		return new ElGamalVerifiableEncryption(encrypt(m, rf),rf);
	}
	
	
	/**
	 * Encrypt message m in the q-order subgroup of Z*_p 
	 * @param m message to encrypt
	 * @param rf random factor to use in the encryption
	 * @return the encrypted message
	 * @throws InvalidParameterException if m >= this.p or m <= 0
	 */
	public final ElGamalEncryption encryptQOrderMessage(BigInteger m, BigInteger rf)
	{
		if (m.compareTo(this.p)>=0 || m.compareTo(BigInteger.ZERO)<=0)
			throw new InvalidParameterException("Message to encrypt must be in Z*_p");
		
		return baseEncryption(m, rf);
	}
	
	/**
	 * Encrypt message m in the q-order subgroup of Z*_p 
	 * It uses a random encryption factor in the range [1, q[.
	 * @param m message to encrypt
	 * @return the encrypted message
	 * @throws InvalidParameterException if m >= this.p or m <= 0
	 */
	public final ElGamalEncryption encryptQOrderMessage(BigInteger m)
	{
		// generate a random encryption factor in the range [1, q[. 
		BigInteger rf = generateRandomFactor();
		return encryptQOrderMessage(m, rf);
	}
	
	/**
	 * Encrypt message m in the q-order subgroup of Z*_p 
	 * It uses a random encryption factor in the range [1, q[.
	 * @param m message to encrypt
	 * @return the encrypted message and the random factor used
	 * @throws InvalidParameterException if m >= this.p or m <= 0
	 */
	public final ElGamalVerifiableEncryption encryptVerifiableQOrderMessage(BigInteger m)
	{
		// generate a random encryption factor in the range [1, q[. 
		BigInteger rf = generateRandomFactor();
		return new ElGamalVerifiableEncryption(encryptQOrderMessage(m, rf),rf);
	}
	
	
	/**
	 * Creates an ElGamal encryption o message m using rf as the encryption factor
	 * @param m message to encrypt
	 * @param rf encryption factor
	 * @return ElGamalEncryption object containing the message encryption
	 */
	private final ElGamalEncryption baseEncryption(BigInteger m, BigInteger rf)
	{
		// x = g^rf mod p
		BigInteger x = this.g.modPow(rf, this.p);
		// y = m.h^rf mod p
		BigInteger y = (m.multiply(this.h.modPow(rf, this.p))).mod(this.p);
		return new ElGamalEncryption(x, y);
	}
	
	
	/**
	 * Encodes message m in Z_q into an element of the q-order group of Z*_p
	 * 
	 * ***** USE ONLY IF p = 2q+1 *****
	 * 
	 * @param m message to encoded
	 * @throws InvalidParameterException if m >= q or m < 0
	 */
	private final BigInteger encodeMessage(BigInteger m)
	{
		if (m.compareTo(this.q)>=0 || m.compareTo(BigInteger.ZERO)<0)
			throw new InvalidParameterException("Message must be in Z_q");
		
		BigInteger M = m.add(BigInteger.ONE);
		if ((M.modPow(this.q, this.p)).compareTo(BigInteger.ONE)==0)
			return M;
		else return this.p.subtract(M);
			
	}
	
	/**
	 * Creates a random factor in [2^bitLength, 2^(bitLength+1)[ (the random factor is always a number of "bitLength" bits)
	 * If this.random is not initialized it initialize itself with the default SecureRandom
	 * @return random number in [2^bitLength, 2^(bitLength+1)[
	 */
	private final BigInteger generateRandomFactor()
	{
		if(this.random==null)
			this.init(new SecureRandom());
		BigInteger r = CryptoUtil.generateRandomNumber(this.q.subtract(BigInteger.ONE), this.random).add(BigInteger.ONE);
		return r;
	}
	
	/**
	 * Verifies the encryption of message m in Z_p
	 * 
	 * ***** USE ONLY IF p = 2q+1 *****
	 * 
	 * @param m message
	 * @param ve verifiable encryption
	 * @return true if ve is a verifiable encryption of m, and false otherwise
	 */
	public final boolean verifyMessageEncryption(BigInteger m, ElGamalVerifiableEncryption ve)
	{
		ElGamalEncryption test = this.encrypt(m , ve.ENCRYPTION_FACTOR);
		return test.equals(ve.MESSAGE_ENCRYPTION);
	}

	/**
	 * Verifies the encryption of message m in the q-order subgroup of Z*_p
	 * @param m message
	 * @param ve verifiable encryption
	 * @return true if ve is a verifiable encryption of m, and false otherwise
	 */
	public final boolean verifyQOrderMessageEncryption(BigInteger m, ElGamalVerifiableEncryption ve)
	{
		ElGamalEncryption test = this.encryptQOrderMessage(m , ve.ENCRYPTION_FACTOR);
		return test.equals(ve.MESSAGE_ENCRYPTION);
	}

	public final String toString(int radix)
	{
		String s = "p = " + this.p.toString(radix) + "\n"
				 + "q = " + this.q.toString(radix) + "\n"
				 + "g = " + this.g.toString(radix) + "\n"
				 + "h = " + this.h.toString(radix);
		return s;
	}
	
	public final String toString()
	{
		return toString(ElGamalKeyParameters.TO_STRING_RADIX);
	}
}
