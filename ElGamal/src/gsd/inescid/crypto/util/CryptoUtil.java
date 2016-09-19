package gsd.inescid.crypto.util;

import gsd.inescid.crypto.ElGamalKeyParameters;

import java.math.BigInteger;
import java.util.Random;

public class CryptoUtil {

	/**
	 * Creates a random number in [2^(bitLength-1), 2^bitLength[ (the random number is always a number of "bitLength" bits)
	 * @param bitLength the size of the random number in bits
	 * @param random randomness source
	 * @return random number in [2^(bitLength-1), 2^bitLength[
	 */
	public static final BigInteger generateRandomNumber(int bitLength, Random random)
	{
		BigInteger base = ElGamalKeyParameters.TWO.pow(bitLength-1);
		BigInteger r = new BigInteger(bitLength-1, random); //random value in [0, 2^(bitLength-1)[ 
		return base.add(r);
	} 
	
	/**
	 * Creates a random number in [0, maxValue[ 
	 * @param maxValue
	 * @param random source of randomness
	 * @return random number in [0, maxValue[
	 */
	public static final BigInteger generateRandomNumber(BigInteger maxValue, Random random)
	{
		BigInteger testValue;
		do{
			testValue = new BigInteger(maxValue.bitLength(), random);
		}while(testValue.compareTo(maxValue) >= 0);
		
		return testValue;
	}
	
	/**
	 * Copy last length bytes of the src array to a new array and returns it
	 * @param src
	 * @param length
	 * @return returns the "length" last bytes of src. 
	 * 			The returned array has always a length of "length". 
	 * 			If src length is less than the desired zero padding bytes are 
	 * 			added to the beginning of the result. 
	 */
	public static byte[] copyLastBytesOf(byte[] src, int length)
	{
		byte[] result = new byte[length];
		length--;
		for(int i = src.length-1; i>=0 && length >= 0; i--, length--)
			result[length] = src[i];
		return result;
	}
	
	/**
	 * Utility method to transform a length in bits into the corresponding length in bytes
	 * @param bitsLength
	 * @return the minimum number of bytes the can hold "bitsLength" bits.
	 */
	public static int getLengthInBytes(int bitsLength)
	{
		int r = bitsLength / 8;
		if (bitsLength%8 != 0)
			r++;
		return r;
	}
	
	/**
	 * Utility method to truncate a value within a byte array to alpha bits.
	 * @param value the value to truncate
	 * @param alpha the number of valid bits
	 * @return a byte array truncated to the minimum bytes necessary to represent 
	 * 			an unsigned alpha bits value. The byte array contains the "value" 
	 * 			truncated to alpha bits. The value is truncated in the left side, 
	 * 			i.e. the bytes returned are those with a higher index. 
	 * 			If alpha is <= 0 it returns the "value" 
	 * 			byte array unmodified. 
	 */
	public static byte[] truncateToAlphaBits(byte[] value, int alpha)
	{
		if (alpha <= 0) 
			return value;
		int length = getLengthInBytes(alpha);
		int aux = alpha % length;
		aux = 8 - aux;
		int adjustment = 0xFF;
	
		while (aux>0)
			adjustment >>>= 1;
		
		byte[] r = copyLastBytesOf(value, length);
		r[0] = (byte)(r[0] & adjustment);
		return r;
	}
}
