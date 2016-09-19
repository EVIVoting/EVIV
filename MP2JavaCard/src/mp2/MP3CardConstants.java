package mp2;

import javacard.security.MessageDigest;

public interface MP3CardConstants {
	public static final short P_LENGTH = 0x80; //1024 bites
	public static final short Q_LENGTH = 0x40; //512 bits
	public static final short MAX_CANDIDATES = 10;
	public static final byte MAX_CANDIDATES_FLAG = 0x0F; // for random yes vote selection 
	public static final byte MESSAGE_DIGEST_ALGORITHM = MessageDigest.ALG_SHA;
	
	public static final short ERR_COMMAND_NOT_ALLOWED         = 0x6900; /* used if an error occurs when checking the  APDU case */
	public static final short ERR_INVALID_CANDIDATE_SELECTION = 0x6901;
	public static final short ERR_WRONG_P1P2                  = 0x6B00;
	public static final short ERR_INS_NOT_SUPPORTED           = 0x6D00;
	public static final short ERR_CLA_NOT_SUPPORTED           = 0x6E00;
	public static final short ERR_NO_PRECISE_DIAGNOSTIC       = 0x6F00;
	public static final short ERR_WRONG_INPUT_LENGTH          = 0x6700;
	public static final short ERR_EXPECTED_P_LENGTH_OUTPUT    = 0x6C80;
	public static final short ERR_EXPECTED_Q_LENGTH_OUTPUT    = 0x6C14;
	public static final short ERR_EXPECTED_ONE_BYTE_OUTPUT    = 0x6C01;
	
	public static final byte VOTE_CODE_LENGTH = 8; /* vote code length */


}
