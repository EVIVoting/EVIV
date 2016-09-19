package mp2;

public class CGS97Proof {
	byte[] a1;
	byte[] a2;
	byte[] b1;
	byte[] b2;
	byte[] c;
	byte[] d1;
	byte[] d2;
	byte[] r1;
	byte[] r2;
	
	public CGS97Proof()
	{
		this.a1 = new byte[MP3CardConstants.P_LENGTH];
		this.a2 = new byte[MP3CardConstants.P_LENGTH];
		this.b1 = new byte[MP3CardConstants.P_LENGTH];
		this.b2 = new byte[MP3CardConstants.P_LENGTH];
		this.c = new byte[MP3CardConstants.Q_LENGTH];
		this.d1 = new byte[MP3CardConstants.Q_LENGTH];
		this.d2 = new byte[MP3CardConstants.Q_LENGTH];
		this.r1 = new byte[MP3CardConstants.Q_LENGTH];
		this.r2 = new byte[MP3CardConstants.Q_LENGTH];
	}
}
