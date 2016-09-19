package gsd.inescid.crypto;

public class ElGamalKeyPair {

	public final ElGamalPublicKey publicKey;
	public final ElGamalPrivateKey privateKey;
	
	public ElGamalKeyPair (ElGamalPublicKey kpub, ElGamalPrivateKey kpri)
	{
		this.publicKey = kpub;
		this.privateKey = kpri;
	}
	
	public final String toString(int radix)
	{
		String s = this.publicKey.toString(radix) + "\n" 
				 + "kpri = " + this.privateKey.kpri.toString(radix);
		return s;
	}
	
	public final String toString()
	{
		return toString(ElGamalKeyParameters.TO_STRING_RADIX);
	}
	
	public final ElGamalKeyParameters getKeyParameters()
	{
		return new ElGamalKeyParameters(this.publicKey.p, this.publicKey.q, this.publicKey.g);
	}
}
