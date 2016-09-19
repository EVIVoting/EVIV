package gsd.inescid.crypto;

import gsd.inescid.crypto.util.Base64;
import gsd.inescid.crypto.util.CryptoUtil;

import java.math.BigInteger;
import java.security.InvalidParameterException;

public final class ElGamalEncryption {
	public final BigInteger X; //g^r
	public final BigInteger Y; //m.h^r
	
	// XML TAGS
	public static final String XML_TAG = "ElGamalEncryption";
	public static final String XML_X_TAG = "X";
	public static final String XML_Y_TAG = "Y";
	
	public final String toXML()
	{
		StringBuilder xml = new StringBuilder();
		xml.append(xml + "<" + XML_TAG + ">\n");
		xml.append("<" + XML_X_TAG + ">" + Base64.encode(this.X.toByteArray()) + "</" + XML_X_TAG + ">\n");
		xml.append("<" + XML_Y_TAG + ">" + Base64.encode(this.Y.toByteArray()) + "</" + XML_Y_TAG + ">\n");
		xml.append(xml + "</" + XML_TAG + ">\n");
		return xml.toString();
	}
	
	public ElGamalEncryption(byte[] X, byte[] Y)
	{
		this.X = new BigInteger(1,X);
		this.Y = new BigInteger(1,Y);
	}
	
	public ElGamalEncryption(BigInteger X, BigInteger Y)
	{
		this.X = X;
		this.Y = Y;
	}
	
	public boolean equals(ElGamalEncryption e)
	{
		if(this.X.equals(e.X) && this.Y.equals(e.Y))
			return true;
		else 
			return false;
	}
	
	public final String toString(int radix)
	{
		String s = "X (g^r)   = " + this.X.toString(radix).toUpperCase() + "\n"
				 + "Y (m.h^r) = " + this.Y.toString(radix).toUpperCase();
		return s;
	}
	
	public final String toString()
	{
		return toString(ElGamalKeyParameters.TO_STRING_RADIX);
	}
	
	/***
	 * This method multiplies the components of this ElGamalEncryption by the components of enc parameters.
	 * It provides an homomorphic multiplication of the encrypted messages.
	 *  
	 * @param enc 
	 * @param modulus the modulus p used in the creation of this encryption. 
	 * @return
	 */
	public final ElGamalEncryption multiply(ElGamalEncryption enc, BigInteger modulus)
	{
		BigInteger newX = (this.X.multiply(enc.X)).mod(modulus);
		BigInteger newY = (this.Y.multiply(enc.Y)).mod(modulus);
		return new ElGamalEncryption(newX, newY);
	}
	
	/***
	 * This method divides the components of this ElGamalEncryption by the components of enc parameters.
	 * It provides an homomorphic division of the encrypted messages.
	 *  
	 * @param enc 
	 * @param modulus the modulus p used in the creation of this encryption. 
	 * @return
	 */
	public final ElGamalEncryption divide(ElGamalEncryption enc, BigInteger modulus)
	{
		BigInteger newX = (this.X.divide(enc.X)).mod(modulus);
		BigInteger newY = (this.Y.divide(enc.Y)).mod(modulus);
		return new ElGamalEncryption(newX, newY);
	}
	
	/**
	 * Convert the BigInteger representation into a byte array representation.
	 * @param modulusByteLength desired modulus length (array length)
	 * @return two byte arrays of length modulusByteLength {{X},{Y}}. The arrays are zero padded as necessary.
	 * @throws InvalidParameterException if the the values stored in X or Y do not fit into the 
	 * 									 specified modulus length.
	 */
	public final byte[][] toByteArray(int modulusByteLength) throws InvalidParameterException
	{
		if (CryptoUtil.getLengthInBytes(this.X.bitLength())>modulusByteLength ||
			CryptoUtil.getLengthInBytes(this.Y.bitLength())>modulusByteLength)
			throw new InvalidParameterException("Specified modulus too small.");
		
		byte[][] r = new byte[2][];
		r[0] = 	CryptoUtil.copyLastBytesOf(this.X.toByteArray(), modulusByteLength);
		r[1] = 	CryptoUtil.copyLastBytesOf(this.Y.toByteArray(), modulusByteLength);
		return r;
	}
}
