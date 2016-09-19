package gsd.inescid.crypto;


import java.math.BigInteger;
import java.security.InvalidParameterException;

public class ElGamalPrivateKey {
	/** a prime such that p = 2*k*q + 1 **/
	public final BigInteger p; 
	/** a prime number **/
	public final BigInteger q;
	/** ElGamal private key(-privateKey mod q for faster decryption) **/
	public final BigInteger kpri; 
	
		
	public ElGamalPrivateKey(ElGamalKeyParameters param, BigInteger privateKey)
	{
		this.p = param.p;
		this.q = param.q;
		this.kpri = this.q.subtract(privateKey); // -privateKey mod q
	}
	
	/**
	 * Decrypts the ElGamal ciphertext c of a Z_q element
	 * 
	 * ***** USE ONLY IF p = 2q+1 *****
	 * 
	 * @param c ciphertext to decrypt
	 * @return the decrypted message in Z_q
	 */
	public final BigInteger decrypt(ElGamalEncryption c)
	{
		return decodeMessage(baseDecryption(c));
	}
	

	/**
	 * Decrypts the ElGamal ciphertext c
	 * @param c ciphertext to decrypt
	 * @return the decrypted message in Z*_p
	 */
	public final BigInteger decryptQOrderMessage(ElGamalEncryption c)
	{
		return baseDecryption(c);
	}

	
	/**
	 * Decrypts the ElGamal ciphertext c
	 * @param c ciphertext to decrypt
	 * @return the decrypted message
	 * @throws InvalidParameterException if the ciphertext elements are not in Z*_p
	 */
	private final BigInteger baseDecryption(ElGamalEncryption c)
	{
		if ( c.X.compareTo(this.p) >= 0 || c.X.compareTo(BigInteger.ZERO) <= 0 
		   ||c.Y.compareTo(this.p) >= 0 || c.Y.compareTo(BigInteger.ZERO) <= 0)
			throw new InvalidParameterException("Invalid ciphertext");
					
		// w = X^kpri mod p
		BigInteger w = c.X.modPow(this.kpri, this.p);
		BigInteger m = (c.Y.multiply(w)).mod(this.p);
		return m;
	}
	
	
	
	
	/**
	 * Decodes message m into a Z_q element
	 * 
	 * ***** USE ONLY IF p = 2q+1 *****
	 * 
	 * @param m message to decoded
	 * @throws InvalidParameterException if m >= p or m <= 0
	 */
	private final BigInteger decodeMessage(BigInteger m)
	{
		if (m.compareTo(this.p)>0 || m.compareTo(BigInteger.ZERO)<=0)
			throw new InvalidParameterException("Message must be in Z*_p");
		BigInteger M;
		if (m.compareTo(this.q) < 0) 
			M = m;
		else M = this.p.subtract(m);
		return M.subtract(BigInteger.ONE);
	}
	
	
	public final String toString(int radix)
	{
		String s = "   p = " + this.p.toString(radix) + "\n"
				 + "   q = " + this.q.toString(radix) + "\n"
				 + "kpri = " + (this.q.subtract(this.kpri)).toString(radix); //recover original private key value
		return s;
	}
	
	public final String toString()
	{
		return toString(ElGamalKeyParameters.TO_STRING_RADIX);
	}
}
