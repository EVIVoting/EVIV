package gsd.inescid.markpledge;

public class ArraysUtil {

	public static void negate(byte[] a)
	{
		for(int i=0; i<a.length; i++)
			a[i] = (byte)~a[i];
	}
	
	public static void logicalAnd(byte[] a, byte[]b, byte[]result)
	{
		for(int i=0; i<a.length; i++)
			result[i] = (byte)(a[i] & b[i]);
	}
	
	public static void logicalOr(byte[] a, byte[]b, byte[]result)
	{
		for(int i=0; i<a.length; i++)
			result[i] = (byte)(a[i] | b[i]);
	}
	
}
