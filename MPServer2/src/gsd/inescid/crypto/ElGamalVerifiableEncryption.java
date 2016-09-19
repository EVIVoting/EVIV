package gsd.inescid.crypto;

import java.math.BigInteger;

public final class ElGamalVerifiableEncryption {

	public final ElGamalEncryption MESSAGE_ENCRYPTION;
	public final BigInteger ENCRYPTION_FACTOR;
	
	public ElGamalVerifiableEncryption(ElGamalEncryption me, BigInteger ef)
	{
		this.MESSAGE_ENCRYPTION = me;
		this.ENCRYPTION_FACTOR = ef;
	}
	
	public final String toString(int radix)
	{
		String s = this.MESSAGE_ENCRYPTION.toString(radix) + "\n" 
				 + "encfactor = " + this.ENCRYPTION_FACTOR.toString(radix);
		return s;
	}
	
	public final String toString()
	{
		return toString(ElGamalKeyParameters.TO_STRING_RADIX);
	}
}
