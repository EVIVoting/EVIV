package gsd.inescid.markpledge.smartclient.apdu;

import gsd.inescid.markpledge.smartclient.CardUtil;



/**
 * GetAPDU
 * 
 * APDU ISO type: 2
 * APDU format: CLA INS P1 P2 LE
 * 
 * @author Rui Joaquim
 */
public enum GetAPDU{
	/*						 					CLA 		INS 		P1 			P2 			LE      */
	GET_PLEDGE		 			(new byte[]{(byte)0xFA, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00}),
	GET_VCODE		 			(new byte[]{(byte)0xFA, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00}),
	GET_VCODE_VALIDITY_FACTOR   (new byte[]{(byte)0xFA, (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00}),
	
	GET_CANDIDATE_ENCRYPTION_X	(new byte[]{(byte)0xFB, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00}),
	GET_CANDIDATE_ENCRYPTION_Y	(new byte[]{(byte)0xFB, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00}),
	
	/*											CLA 		INS 		P1 			P2 			LE      */
	GET_CGS97_A1				(new byte[]{(byte)0xFC, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00}),
	GET_CGS97_A2				(new byte[]{(byte)0xFC, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00}),
	GET_CGS97_B1				(new byte[]{(byte)0xFC, (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00}),
	GET_CGS97_B2				(new byte[]{(byte)0xFC, (byte)0x03, (byte)0x00, (byte)0x00, (byte)0x00}),
	GET_CGS97_C					(new byte[]{(byte)0xFD, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00}),
	GET_CGS97_D1				(new byte[]{(byte)0xFD, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00}),
	GET_CGS97_D2				(new byte[]{(byte)0xFD, (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00}),
	GET_CGS97_R1				(new byte[]{(byte)0xFD, (byte)0x03, (byte)0x00, (byte)0x00, (byte)0x00}),
	GET_CGS97_R2				(new byte[]{(byte)0xFD, (byte)0x04, (byte)0x00, (byte)0x00, (byte)0x00}),
	GET_SUM_VALIDITY_FACTOR		(new byte[]{(byte)0xFD, (byte)0x05, (byte)0x00, (byte)0x00, (byte)0x00}),

	GET_MP1A_BMP_CONFORMITY_FACTOR(new byte[]{(byte)0xFD, (byte)0xFF, (byte)0x00, (byte)0x00, (byte)0x00}),
			
	GET_VOTE_ENCRYPTION_SIGNATURE (new byte[]{(byte)0xFE, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00}),
	GET_VOTE_AND_RECEIPT_SIGNATURE(new byte[]{(byte)0xFE, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00}),
	GET_VOTE_HASH 				  (new byte[]{(byte)0xFE, (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00}),
	GET_VOTE_AND_RECEIPT_HASH	  (new byte[]{(byte)0xFE, (byte)0x03, (byte)0x00, (byte)0x00, (byte)0x00});
	
	private final byte[] APDUbytes;

	GetAPDU(byte[] bytes){
		this.APDUbytes = bytes;
	}

	public byte[] getAPDUBytes(){
		return this.APDUbytes;
	}

	public String getAPDUText(){
		return CardUtil.bytesToText(getAPDUBytes());
	}
	
	public void setP1(int p1)
	{
		switch(this)
		{
		case GET_VCODE:
		case GET_VCODE_VALIDITY_FACTOR:
		case GET_CANDIDATE_ENCRYPTION_X:
		case GET_CANDIDATE_ENCRYPTION_Y:
		case GET_MP1A_BMP_CONFORMITY_FACTOR:
			this.APDUbytes[APDUConstants.P1_OFFSET] = (byte) p1;
			break;
		default:
			throw new IllegalStateException("P1 is not configurable in the " + this + " APDU");
		}
	}
	
	public void setP2(int p2)
	{
		switch(this)
		{
		case GET_VCODE_VALIDITY_FACTOR:
		case GET_MP1A_BMP_CONFORMITY_FACTOR:
			this.APDUbytes[APDUConstants.P2_OFFSET] = (byte) p2;
			break;
		default:
			throw new IllegalStateException("P2 is not configurable in the " + this + " APDU");
		}
	}

	public void setP1P2(int p1, int p2)
	{
		setP1(p1);
		setP2(p2);
	}
	
	
	public static final int GET_APDU_LE_OFFSET = 4;
	public void setExpectedResponceLength(int le)
	{
		this.APDUbytes[GET_APDU_LE_OFFSET] = (byte) le;
	}
	
}