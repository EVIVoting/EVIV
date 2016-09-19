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
	 * @return
	 */
	public static byte[] copyLastBytesOf(byte[] src, int length)
	{
		byte[] result = new byte[length];
		length--;
		for(int i = src.length-1; i>=0 && length >= 0; i--, length--)
			result[length] = src[i];
		return result;
	}
}
