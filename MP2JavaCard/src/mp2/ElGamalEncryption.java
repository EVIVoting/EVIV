package mp2;

public class ElGamalEncryption {

	byte[] x; //holds g^r
	byte[] y; //holds h^r.m
	
	public ElGamalEncryption()
	{
		this.x = new byte[MP3CardConstants.P_LENGTH];
		this.y = new byte[MP3CardConstants.P_LENGTH];
	}
}
