package gsd.inescid.markpledge.smartclient;


import gsd.inescid.crypto.util.CryptoUtil;
import gsd.inescid.markpledge.MarkPledgeType;
import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.mp2.MP2Parameters;
import gsd.inescid.markpledge.smartclient.connection.IMPCardConnection;
import gsd.inescid.markpledge.smartclient.connection.ISmartCardInterface;
import gsd.inescid.markpledge.smartclient.connection.MP1ACardConnection;
import gsd.inescid.markpledge.smartclient.connection.MP1CardConnection;
import gsd.inescid.markpledge.smartclient.connection.MP2CardConnection;
import gsd.inescid.markpledge.smartclient.connection.MP2WithHelpCardConnection;
import gsd.inescid.markpledge.smartclient.connection.MP3CardConnection;

import java.math.BigInteger;
import java.util.Scanner;

/**
 * Card utility functions
 * 
 * @author Rui Joaquim
 *
 */
public class CardUtil {

	/**
	 * Byte array to string conversion
	 * @param arr the byte array to convert
	 * @return a Sting of the form: "xx xx xx... xx xx". xx represents the hexadecimal
	 *  value of the corresponding byte in arr, in a two symbol format.  
	 */
	public static String bytesToText(byte[] arr)
	{
		StringBuilder sb = new StringBuilder(arr.length * 3);
		sb.append(String.format("%02x", arr[0]));
		
		for(int i = 1; i < arr.length; i++)
			sb.append(String.format(" %02x", arr[i]));
		
		return sb.toString();
	}
	
	/**
	 * Converts a String text into the corresponding byte[] 
	 * @param text String text in the format "xx xx xx... xx xx". The xx value is assumed
	 * 			to be in hexadecimal.
	 * @return the corresponding byte array
	 */
	public static byte[] textToBytes(String text)
	{
		if(text.length() == 0)
			return new byte[0];
		
		byte[] bar = new byte[(text.length()+1) /3];
		Scanner s = new Scanner(text);
		String aux;
		int i = 0;
		while(s.hasNext())
		{
			aux = s.next();
			bar[i] = (byte) Integer.parseInt(aux,16);
			i++;
		}
		return bar;
	}
	
	/**
	 * Concatenates two byte arrays.
	 * @param arr1
	 * @param arr2
	 * @return new byte array = arr1|arr2
	 */
	public static byte[] concatenateArrays(byte[] arr1, byte[] arr2){
		byte[] arr3 = new byte[arr1.length + arr2.length];
		System.arraycopy(arr1, 0, arr3, 0, arr1.length);
		System.arraycopy(arr2, 0, arr3, arr1.length, arr2.length);
		return arr3;
	}
		
	
	/**
	 * Converts a BigInteger value to an array of "size" bytes
	 * @param v the BigInteger value to convert
	 * @param size the size of the return array
	 * @return returns a byte array of size "size" with a copy of the least significant "size" bytes 
	 * 			of the v.toByteArray() result. The returned array is padded with leading zeros if necessary.
	 */
	public static byte[] bigIntegerToByteArray(BigInteger v, int size)
	{
		byte[] vBytes = v.toByteArray();
		if(vBytes.length == size)
			return vBytes;
		
		byte[] result = new byte[size];
		for(int ir=result.length-1, iv=vBytes.length-1; ir>=0 && iv>=0; ir--, iv--)
			result[ir] = vBytes[iv];
		return result;
	}
	
	public static IMPCardConnection getCardConnection(IMPParameters param, MarkPledgeType ballotType, ISmartCardInterface cardInterface, boolean showTimes)
	{
		switch(ballotType)
		{
			case MP1:
				return new MP1CardConnection(param.getPLengthInBytes(), param.getQLengthInBytes(), param.getVoteCodeByteLength(),
										showTimes, cardInterface, param.getAlpha());
			case MP1A:
				return new MP1ACardConnection(param.getPLengthInBytes(), param.getQLengthInBytes(), param.getVoteCodeByteLength(),
										showTimes, cardInterface, param.getAlpha());
			case MP2:
				return new MP2CardConnection(param.getPLengthInBytes(), param.getQLengthInBytes(), param.getVoteCodeByteLength(),
								CardConstants.ALPHA_MAX_VALUE/8,	showTimes, cardInterface);
			case MP2_WITH_HELP:
				return new MP2WithHelpCardConnection((MP2Parameters) param, showTimes, cardInterface);
			case MP3:
				return new MP3CardConnection(param.getPLengthInBytes(), param.getQLengthInBytes(), param.getVoteCodeByteLength(),
						param.getQLengthInBytes(), showTimes, cardInterface);
			default:
				return null;
		}
	}
	
	
}
