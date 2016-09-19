package gsd.inescid.markpledge.smartclient.apdu;
import gsd.inescid.markpledge.smartclient.CardUtil;



/**
 * ActionAPDU
 * 
 * APDU ISO type: 1 (PREPARE_BALLOT, CREATE_CANDIDATE_ENCRYPTION, CREATE_CGS97_CANDIDATE_PROOF, CREATE_MP2_CANONICAL_VOTE)
 * APDU ISO type: 3 (PREPARE_RECEIPT, CREATE_CANONICAL_VOTE_WITH_HELP)
 * APDU ISO type: 4 (SELECT_CANDIDATE)
 * APDU format: CLA INS P1 P2 [LC Data [LE]]
 * 
 * @author Rui Joaquim
 */
public enum ActionAPDU {
	/*				  		   							CLA 		INS 		P1 			P2 		  LC    */
	PREPARE_BALLOT 			   			(new byte[]{(byte)0xF5, (byte)0x00, (byte)0x00, (byte)0x00}),
	CREATE_CANDIDATE_ENCRYPTION			(new byte[]{(byte)0xF5, (byte)0x01, (byte)0x00, (byte)0x00}),
	CREATE_CGS97_CANDIDATE_PROOF		(new byte[]{(byte)0xF5, (byte)0x02, (byte)0x00, (byte)0x00}),
	CREATE_MP2_CANONICAL_VOTE  			(new byte[]{(byte)0xF5, (byte)0xFF, (byte)0x00, (byte)0x00}),
	SELECT_CANDIDATE  		   			(new byte[]{(byte)0xF6, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00}),
	PREPARE_RECEIPT	  		   			(new byte[]{(byte)0xF7, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00}),
	CREATE_MP2_CANONICAL_VOTE_WITH_HELP (new byte[]{(byte)0xF7, (byte)0xFF, (byte)0x00, (byte)0x00, (byte)0x00});


	private final byte[] APDUbytes;
	private final byte[] byte1 = new byte[]{0x01};
	
	ActionAPDU(byte[] bytes){
		this.APDUbytes = bytes;
	}

	
	public byte[] getAPDUBytes(byte[] data){
		switch (this)
		{
			case PREPARE_BALLOT:
			case CREATE_CANDIDATE_ENCRYPTION:
			case CREATE_CGS97_CANDIDATE_PROOF:
			case CREATE_MP2_CANONICAL_VOTE:
				if (data!=null)
					throw new IllegalStateException(this + " APDU does not have data.");
				return this.APDUbytes;
		}
		this.APDUbytes[APDUConstants.LC_OFFSET] = (byte)data.length;
		if(this == SELECT_CANDIDATE)
		{
			data = CardUtil.concatenateArrays(data, byte1);
		}
		return CardUtil.concatenateArrays(this.APDUbytes, data);
	}

	public String getAPDUText(byte[] data){
		return CardUtil.bytesToText(getAPDUBytes(data));
	}
	
	public void setP1(int p1)
	{
		switch(this)
		{
		case PREPARE_BALLOT:
		case CREATE_CANDIDATE_ENCRYPTION:
		case CREATE_CGS97_CANDIDATE_PROOF:
		case CREATE_MP2_CANONICAL_VOTE_WITH_HELP:
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
		case PREPARE_BALLOT:
		case CREATE_MP2_CANONICAL_VOTE_WITH_HELP:
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
}

