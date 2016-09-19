package gsd.inescid.markpledge3;

import java.math.BigInteger;

public class MP3VerificationValues {
	
	public final BigInteger VERIFICATION_VALUE;
	public final BigInteger ENCRYPTION_FACTOR;
	
	public MP3VerificationValues(BigInteger encryptedValue, BigInteger encrytionFactor)
	{
		this.VERIFICATION_VALUE = encryptedValue;
		this.ENCRYPTION_FACTOR = encrytionFactor;
	}
	
	public String toString()
	{
		String s =   "Verification value = " + this.VERIFICATION_VALUE
				 + "\nEncryption verification factor = " + this.ENCRYPTION_FACTOR;
		return s;
	}

}
