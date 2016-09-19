package gsd.inescid.crypto;

import gsd.inescid.crypto.util.Base64;

import java.math.BigInteger;

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
		String s = "X (g^r)   = " + this.X.toString(radix) + "\n"
				 + "Y (m.h^r) = " + this.Y.toString(radix);
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
}
