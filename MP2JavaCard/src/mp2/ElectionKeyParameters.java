package mp2;

public class ElectionKeyParameters {
	byte[] p; 		/* p value (p criptographic modulus)*/
    byte[] q; 		/* q value (q criptographic modulus and sub group order)*/
    byte[] g; 		/* Base generator */
    byte[] h; 		/* h = g^x is the public key, where x is the private key */
    byte[] mp3G; 		/* Generator used to encode the message. It can be equal to g. */
    byte[] mp3GInv; 	/* mp3G ^ -1 */
    
    public ElectionKeyParameters()
    {
    	this.p = new byte[MP3CardConstants.P_LENGTH];
    	this.q = new byte[MP3CardConstants.Q_LENGTH];
    	this.g = new byte[MP3CardConstants.P_LENGTH];
    	this.h = new byte[MP3CardConstants.P_LENGTH];
    	this.mp3G = new byte[MP3CardConstants.P_LENGTH];
    	this.mp3GInv = new byte[MP3CardConstants.P_LENGTH];
    }
}
