package mp2;

public class CandidateEncryption {
	ElGamalEncryption be;
	ElGamalEncryption ce;
	
	public CandidateEncryption()
	{
		this.be = new ElGamalEncryption();
		this.ce = new ElGamalEncryption();
	}
}
