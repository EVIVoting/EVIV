package gsd.inescid.crypto.util;

/**
 * 
 * @author Rui
 *
 * Base 64 encoding and decoding as described in RFC3548
 */
public class Base64 {
	public static final String ALPHABET= 
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789+/";
	
	private static final int MASK_6_BITS  = 0x3F;
	private static final int MASK_8_BITS  = 0xFF;
	
	private static final int VERIFY_MASK_2_BITS  = 0x3C;
	private static final int VERIFY_MASK_4_BITS  = 0x30;
	
	/**
	 * Encodes the bytes in m as a base 64 string
	 * @param m the message to encode
	 * @return base 64 representation of m
	 */
	public static final String encode(byte[] m)
	{
		if (m == null)
			return null;
			
		boolean isNecessaryPadBytes = m.length % 3 != 0; //adjustment to 24 bits blocks
		
		StringBuilder encodedMessage = new StringBuilder(m.length/3*4 + (isNecessaryPadBytes?4:0));
		
		for(int i=0; i < m.length-2; i+=3) //24 bits jump
		{
			encodedMessage.append(encodeBytes(i, m));
		}
		
		if (isNecessaryPadBytes)
			encodedMessage.append(encodeFinalBytes((m.length/3)*3, m));
		
		return encodedMessage.toString();
	}
	
	
	/**
	 * Encode into base 64 3 bytes of message m starting at index
	 * @param index start index
	 * @param m message to encode
	 * @return the 3 bytes in base 64
	 * @throws IndexOutOfBoundsException if index < 0 and index >= m.length-2
	 */
	private static final StringBuilder encodeBytes(int index, byte[] m)
	{
		int characterIndex, aux;
		StringBuilder encoding = new StringBuilder(4);
		
		//first character
		characterIndex = m[index] >>> 2;
		characterIndex = characterIndex & MASK_6_BITS;
		encoding.append(ALPHABET.charAt(characterIndex));
		
		//second character
		characterIndex = m[index] << 4;
		aux = (m[index+1] & MASK_8_BITS) >>> 4;
		characterIndex = characterIndex | aux;
		characterIndex = characterIndex & MASK_6_BITS;
		encoding.append(ALPHABET.charAt(characterIndex));
		
		//third character
		characterIndex = m[index+1] << 2;
		aux = (m[index+2] & MASK_8_BITS) >>> 6;
		characterIndex = characterIndex | aux;
		characterIndex = characterIndex & MASK_6_BITS;
		encoding.append(ALPHABET.charAt(characterIndex));
		
		//fourth character
		characterIndex = m[index+2] & MASK_6_BITS;
		encoding.append(ALPHABET.charAt(characterIndex));
		
		return encoding;
	}
	
	/**
	 * Encode into base 64 3 bytes of message m starting at index and adding padding as necessary
	 * @param index start index
	 * @param m message to encode
	 * @return the 3 bytes in base 64 with padding (if necessary)
	 * @throws IndexOutOfBoundsException if index < 0 and index >= m.length-2
	 */
	private static final StringBuilder encodeFinalBytes(int index, byte[] m)
	{
		if(m.length == index)
			return null;
		
		else if ( m.length > index + 2)
			return encodeBytes(index, m);
		
		else
		{
			byte[] aux = new byte[3];
			for(int i=0, k=index; i<3 && k<m.length; i++, k++)
				aux[i] = m[k];
			
			int missingBytes = 3 - (m.length % 3); //24 bits blocks
			StringBuilder encoding = (StringBuilder) encodeBytes(0, aux);
			for(int i = encoding.length()-1; missingBytes > 0; i--, missingBytes--)
				encoding.setCharAt(i, '=');
			
			return encoding;
		}
	}
	
	
	
	
	/**
	 * Decodes the base64 string m into the corresponding byte array 
	 * @param m the message to decode
	 * @return the byte array that corresponds to m
	 * @throws IllegalArgumentException if message length is not a multiple of 4
	 * @throws IllegalArgumentException if the message contains any invalid character
	 */
	public static final byte[] decode(String m)
	{
		int equalsSignIndex = m.indexOf('=');
		int bytesToRemove = m.length() - equalsSignIndex;
				
		if(m.length()%4 != 0)
			throw new IllegalArgumentException("Invalid message length.");
		
		if (bytesToRemove > 0)
		{
			int verifyMask;
			boolean invalidMessage = false;
			int c;
			switch(bytesToRemove)
			{
				case 1:
					verifyMask = VERIFY_MASK_2_BITS;
					c = decodeChar(m.charAt(m.length()-2));
					if ((c & verifyMask) != c)
						invalidMessage = true;
					break;
					
				case 2:
					verifyMask = VERIFY_MASK_4_BITS;
					c = decodeChar(m.charAt(m.length()-3));
					if ((c & verifyMask) != c || m.charAt(m.length()-1) != '=')
						invalidMessage = true;
					break;
					
			 	default: 
			 		invalidMessage = true;
			}
			
			if (invalidMessage)
				throw new IllegalArgumentException("Invalid message.");
			
		}
		
		
		
		int byteArrayLength = m.length()/4*3;
		int byteArrayIndex = 0;
		byte[] aux, decodedMessage = new byte[byteArrayLength];
		
		for(int i=0; i < m.length(); i+=4)
		{
			aux = decode(i, m);
			for(int k=0;  k < aux.length; k++, byteArrayIndex++)
				decodedMessage[byteArrayIndex] = aux[k];
		}
		
		
		
		if(bytesToRemove == 0)
			return decodedMessage;
		else
		{
			byte[] newOutput = new byte[decodedMessage.length - bytesToRemove];
			for(int i=0; i < newOutput.length; i++)
				newOutput[i] = decodedMessage[i];
			return newOutput;
		}
			
	}
	
	
	/**
	 * Decodes 4 characters (starting at index) of the base64 string m
	 * into the corresponding byte array 
	 * @param index starting index
	 * @param m the message to decode
	 * @return the byte array that corresponds to m
	 * @throws IllegalArgumentException if the message contains any invalid character
	 * @throws NullPointerException if index is not a valid index of m
	 */
	private static final byte[] decode(int index, String m)
	{
		byte[] decodedMessage = new byte[3];
		int aux1, aux2;
		
		//first byte
		aux1 = decodeChar(m.charAt(index));
		aux2 = decodeChar(m.charAt(index+1));
		decodedMessage[0] = (byte)(((aux1 << 2) | (aux2 >>> 4)) & MASK_8_BITS);
		
		//second byte
		aux1 = decodeChar(m.charAt(index+1));
		aux2 = decodeChar(m.charAt(index+2));
		decodedMessage[1] = (byte)(((aux1 << 4) | (aux2 >>> 2)) & MASK_8_BITS);
		
		//third byte
		aux1 = decodeChar(m.charAt(index+2));
		aux2 = decodeChar(m.charAt(index+3));
		decodedMessage[2] = (byte)(((aux1 << 6) | aux2) & MASK_8_BITS);
		
		return decodedMessage;
	}
	
	
	
	/**
	 * Gets the int value of a base 64 character
	 * @param c the character to decode
	 * @return the int value of c
	 * @throws IllegalArgumentException if c is an invalid character
	 */
	private static final int decodeChar(char c)
	{
		if(c >= 'A' && c <= 'Z') //uppercase
			return c - 'A';
		
		else if(c >= 'a' && c <= 'z') //lowercase
			return c - 'a' + 26;
		
		else if(c >= '0' && c <= '9') //uppercase
			return c - '0' + 52;
		
		else
		{
			switch(c)
			{
				case '+' : return 62;
				case '/' : return 63;
				case '=' : return 0; //Padding
				default: throw new IllegalArgumentException("Illegal char in base64 message");
			}
		}
	}
	
	
	public static void main(String[] args)
	{
		String m1 = "FPucAwE=";
		byte[] b1 = decode(m1);
		System.out.println("\nM1: " + m1 +
						   "\nD1: " + toPositiveString(b1) +
						   "\nE1: " + encode(b1));
	}
	
	public static String toPositiveString(byte[] array)
	{
		StringBuilder s = new StringBuilder();
		s.append("[" + (array[0] & MASK_8_BITS));
		for(int i=1; i < array.length; i++)
			s.append(", " + (array[i] & MASK_8_BITS));
		s.append("]");
		return s.toString();
	}
}
