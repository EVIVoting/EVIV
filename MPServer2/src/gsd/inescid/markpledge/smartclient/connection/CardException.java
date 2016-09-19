package gsd.inescid.markpledge.smartclient.connection;

import gsd.inescid.markpledge.smartclient.CardUtil;

import java.util.Arrays;

@SuppressWarnings("serial")
public class CardException extends Exception {

	public enum MP3Exceptions{
		ERR_COMMAND_NOT_ALLOWED 		(new byte[]{(byte) 0x69, (byte) 0x00}),
		ERR_INVALID_CANDIDATE_SELECTION (new byte[]{(byte) 0x69, (byte) 0x01}), 
		ERR_WRONG_P1P2                  (new byte[]{(byte) 0x6B, (byte) 0x00}),
		ERR_INS_NOT_SUPPORTED           (new byte[]{(byte) 0x6D, (byte) 0x00}),
		ERR_CLA_NOT_SUPPORTED           (new byte[]{(byte) 0x6E, (byte) 0x00}),
		ERR_NO_PRECISE_DIAGNOSTIC       (new byte[]{(byte) 0x6F, (byte) 0x00}),
		ERR_WRONG_INPUT_LENGTH          (new byte[]{(byte) 0x67, (byte) 0x00}),
		ERR_EXPECTED_P_LENGTH_OUTPUT    (new byte[]{(byte) 0x6C, (byte) 0x80}),
		ERR_EXPECTED_Q_LENGTH_OUTPUT    (new byte[]{(byte) 0x6C, (byte) 0x14}),
		ERR_EXPECTED_ONE_BYTE_OUTPUT    (new byte[]{(byte) 0x6C, (byte) 0x01});
		
		private final byte[] value;
		
		private MP3Exceptions(byte[] value) {
			this.value = value;
		}
		
		public boolean matchValue(byte[] value)
		{
			if(this == ERR_COMMAND_NOT_ALLOWED && value[0] == 0x69 && value[1] != 0x01)
				return true;
			return Arrays.equals(this.value, value);
		}
		
	}
	
	/**
	 * Creates the exception message from the 
	 * @param value
	 */
	public CardException (byte[] value, byte[] command){
		super(getExceptionMessage(value) + " originated by: " +CardUtil.bytesToText(command));
	}
	
	
	public static String getExceptionMessage(byte[] value){
		
		if(value.length != 2)
			return "Invalid error value: " + CardUtil.bytesToText(value);
			
		for(MP3Exceptions e : MP3Exceptions.values())
			if (e.matchValue(value))
				return e.toString() + ": " + CardUtil.bytesToText(value);
		 
		return "Cannot identify error: " + CardUtil.bytesToText(value);
	}
}
