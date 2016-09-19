package gsd.inescid.markpledge.smartclient.apdu;

import gsd.inescid.markpledge.smartclient.CardUtil;

/**
 * SetAPDU
 * 
 * APDU ISO type: 1 (SET_ALPHA)
 * APDU ISO type: 3 (all except SET_ALPHA)
 * APDU general format: CLA INS P1 P2 LC Data
 * 
 * @author Rui Joaquim
 */
public enum SetAPDU {
	/*						 			CLA 		INS 		P1 			P2 			LC      */
	SET_P				 (new byte[]{(byte)0xF0, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00}),
	SET_G				 (new byte[]{(byte)0xF0, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00}),
	SET_H				 (new byte[]{(byte)0xF0, (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00}),
	SET_MP_G			 (new byte[]{(byte)0xF0, (byte)0x03, (byte)0x00, (byte)0x00, (byte)0x00}),
	SET_MP_GINV			 (new byte[]{(byte)0xF0, (byte)0x04, (byte)0x00, (byte)0x00, (byte)0x00}),
	SET_Q				 (new byte[]{(byte)0xF1, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00}),
	SET_MP2_GV_X 		 (new byte[]{(byte)0xF1, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00}),
	SET_MP2_GV_Y 		 (new byte[]{(byte)0xF1, (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00}),
	SET_LAMBDA_MULTIPLIER(new byte[]{(byte)0xF1, (byte)0x03, (byte)0x00, (byte)0x00, (byte)0x00}),
	SET_LAMBDA  		 (new byte[]{(byte)0xF2, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00}),
	SET_ALPHA	  		 (new byte[]{(byte)0xF3, (byte)0x00, (byte)0x00, (byte)0x00});

	private final byte[] APDUbytes;

	SetAPDU(byte[] bytes){
		this.APDUbytes = bytes;
	}
	
	public byte[] getAPDUBytes(byte[] data){
		if(this == SET_ALPHA)
			if (data != null)
				throw new IllegalStateException(this + " APDU does not have data.");
			else
				return this.APDUbytes;
				
		this.APDUbytes[APDUConstants.LC_OFFSET] = (byte)data.length;
		return CardUtil.concatenateArrays(this.APDUbytes, data);
	}
	
	public String getAPDUText(byte[] data){
		return CardUtil.bytesToText(getAPDUBytes(data));
	}
		
	public void setP1(int p1)
	{
		if(this == SET_ALPHA)
			this.APDUbytes[APDUConstants.P1_OFFSET] = (byte)p1;
		else
			throw new IllegalStateException("P1 is not configurable in the " + this + " APDU");
	}
	
}