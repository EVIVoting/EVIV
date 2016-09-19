package mp3;


import javacard.security.RSAPrivateKey;
import javacardx.crypto.Cipher;


/**
 * Utility class to deal with large UNSIGNED integers.
 * This class offers only static utility methods and does not allocate any memory.
 * 
 * @author Rui Joaquim
 */
public class MP3MathUti {
    
	public static final byte[] TWO = new byte[]{2};
    
	public static final short BMASK = 0x00FF;
    private static final short ONE_BIT_MASK = 0x0001;
    private static final short TWO_BIT_MASK = 0x0003;
    
    /**
     * Method that adds two byte arrays r = (a+b mod 2^a.length).
     * Requires: a.length == b.length
     * 			 r.length >= a.length 
     * Supports parameters overlapping (r == a or r == b).
     * @param a 
     * @param b
     * @param r the result of the sum is stored in the bytes [r.length-a.length to r.length-1].
     * @return true if the sum modulus 2^a.length generates a carry  
     */
    public static boolean add(byte[]a, byte[]b, byte[]r)
    {
        short idx = (short) (a.length - 1);
        short idxR = (short) (r.length - 1);
        
        short v = 0;

    	while (idx >= 0)
        {
            v += (((short)a[idx]) & BMASK) + (((short)b[idx]) & BMASK);
            r[idxR] = (byte)v;
            v >>>= 8;
            idx--;
            idxR--;
        }
        if(v>0) return true;
        else return false;
    }
   

    /**
     * Method that subtracts two byte arrays r = (a-b mod 2^a.length).
     * Requires: a.length == b.length
     * 			 r.length >= a.length
     * Supports parameters overlapping (r == a or r == b). 
     * @param a 
     * @param b
     * @param r the result of the subtraction is stored in the bytes [r.length-a.length to r.length-1].
     * @return true if the subtraction modulus 2^a.length generates a borrow.  
     */
    public static boolean subtract(byte[]a, byte[]b, byte[] r)
    {
     	short idx = (short) (a.length - 1);
    	short v = 0;
    	short borrow = 0;

        while (idx >= 0)
        {
            v = (short)((((short)a[idx]) & BMASK) - (((short)b[idx]) & BMASK) - borrow);
            r[idx] = (byte)v;
            borrow = (v < 0) ? (short)1 : (short)0;
            idx--;
         }
        if(borrow == 1) return true;
        else return false;
    }
    
    
    /**
     * Compares the arrays a and b taking the byte values as unsigned integer values.
     * Requires: a.length == b.length.
     * @param a
     * @param b
     * @return 1 if a > b, 0 if a== b or -1 if a < b.
     */
    public static short compareArrays(byte[] a, byte[]b)
	{
		for(short i = 0; i < a.length; i++)
		{
			if((a[i] & BMASK) > (b[i] & BMASK))
				return 1;
			if((a[i] & BMASK) < (b[i] & BMASK))
				return -1;
		}
		return (short)0;
	}
   
     
    
    
    /**
     * Method that adds two byte arrays modulus m -> r = (a+b mod m).
     * Requires: a.length == b.length == r.length == m.length
     * Supports parameters overlapping (r == a or r == b).
     * @param a
     * @param b
     * @param r  
     * @param m
     */
    public static void addMod(byte[] a, byte[] b , byte[] r, byte[] m){
		if(add(a, b, r) || compareArrays(r, m) >= 0 )
			subtract(r, m, r);
	}
    
    /**
     * Method that subtracts two byte arrays modulus m -> r = (a+b mod m).
     * Requires: a.length == b.length == r.length == m.length
     * Supports parameters overlapping (r == a or r == b).
     * @param a
     * @param b
     * @param r  
     * @param m
     */
     public static void subtractMod(byte[] a, byte[] b , byte[] r, byte[] m){
		if(subtract(a, b, r))
			add(r, m, r);
	}
    
     
    /**
     * Method that performs a right shift on the array a.
     * Supports only shift == 1 or shift == 2. In the case of an invalid value of shift nothing is done. 
     * @param a
     * @param shift the number of bits to shift.
     */ 
    public static void shiftRight(byte[] a, short shift)
    {
    	short bitMask;
    	switch(shift)
    	{
    		case 1: bitMask = ONE_BIT_MASK;
    				break;
    		case 2: bitMask = TWO_BIT_MASK;
					break;
    		default: return;
    	}
    	
    	short oldTransfer = 0, newTransfer;
    	short transferShift = (short)(8 - shift); 
    	for(short i=0; i< a.length; i++)
    	{
    		newTransfer = (short)(a[i] & bitMask);
    		newTransfer = (short)(newTransfer << transferShift);
    		a[i] = (byte)(((a[i] & BMASK) >>> shift) | oldTransfer);
    		oldTransfer = newTransfer;
    	}
    }
    
    /**
     * Method that devides the value in the array a by two modulus m.
     * @param a At the end of this method we have a = a/2 mod m.
     * @param m
     */
    public static void divideBy2Mod(byte[] a, byte[] m){
    	short lsb = (short)(a[a.length-1] & ONE_BIT_MASK);
    	if(lsb==0)
    	{
    		shiftRight(a, (short)1);
    	}
    	else
    	{
    		boolean carry = add(a, m, a);
    		shiftRight(a, (short)1);
    		if (carry) 
    			a[0] = (byte)(a[0] | 0x0080);
    	}
	
    }

    /**
     * Method that devides the value in the array a by four modulus m.
     * @param a At the end of this method we have a = a/4 mod m.
     * @param m
     */
     public static void divideBy4Mod(byte[] a, byte[] m)
    {
    	short ls2b = (short)(a[a.length-1] & TWO_BIT_MASK);
    	if(ls2b==0)
    	{
    		shiftRight(a, (short)2);
    	} 
    	else 
    	{
    		divideBy2Mod(a, m);
    		divideBy2Mod(a, m);
    	}
    }

     
    /**
     * This method performs a modular exponentiation: r = a^e mod m.
     * Requires: rsaCipher must be an instance of Cipher implementing the Cipher.ALG_RSA_NOPAD algorithm.
     * 			 the size of m in bits must be equal to key.getSize().
     * 			 a.length <= m.length && a < m.
     *   		 r must be transient memory.
     * Supports parameters overlapping (e.g. a==r).
     * @param a
     * @param e
     * @param m
     * @param r
     * @param key
     * @param rsaCipher
     */ 
 	public static void modPow(byte[] a, byte[] e, byte[] m, byte[] r, RSAPrivateKey key, Cipher rsaCipher) {
		key.setModulus(m, (short)0, (short)m.length);
		key.setExponent(e, (short)0, (short)e.length);
		rsaCipher.init(key, Cipher.MODE_ENCRYPT);
		rsaCipher.doFinal(a, (short)0, (short)a.length, r, (short)0);
	}
	
 	/**
     * This method performs a modular exponentiation: r = a^e mod m.
     * Requires: rsaCipher must be an instance of Cipher implementing the Cipher.ALG_RSA_NOPAD algorithm.
     * 			 the modulus of the key (m) must be already set.
     * 			 a.length <= m.length && a < m.
     *   		 r must be transient memory.
     * Supports parameters overlapping (e.g. a==r).
     * @param a
     * @param e
     * @param r
     * @param key
     * @param rsaCipher
     */ 
 	public static void modPow(byte[] a, byte[] e, byte[] r, RSAPrivateKey key, Cipher rsaCipher) {
		key.setExponent(e, (short)0, (short)e.length);
		rsaCipher.init(key, Cipher.MODE_ENCRYPT);
		rsaCipher.doFinal(a, (short)0, (short)a.length, r, (short)0);
	}
 	
 	
 	
 	/**
 	 * This method performs a modular multiplication and stores the result in r: r = a.b mod m
 	 * The calculus based on the following formula: (a+b)^2 - (a-b)^2 = 4.a.b mod m
 	 * Requires: a.length == b.length == m.length == r.length == aux.length.
 	 * 			 rsaCipher must be an instance of Cipher implementing the Cipher.ALG_RSA_NOPAD algorithm.
     * 			 the size of m in bits must be equal to key.getSize().
     * 			 r and aux must be transient memory.
 	 * Supports parameters overlapping (a == r or b == r).
 	 * @param a
 	 * @param b
 	 * @param m
 	 * @param r
 	 * @param aux auxiliary array to store intermediate results. At the end it contains (a+b)^2 mod m. 
 	 * @param key
 	 * @param rsaCipher Cipher instance to perform the square function.
 	 */
	public static void modMult(byte[] a, byte[] b, byte[] m, byte[] r, byte[] aux, RSAPrivateKey key, Cipher rsaCipher)  
	{			
		key.setModulus(m, (short)0, (short)m.length);
		key.setExponent(TWO, (short)0, (short)TWO.length);
		rsaCipher.init(key, Cipher.MODE_ENCRYPT);

		modMult(a, b, m, r, aux, rsaCipher);
	}
	
 	/**
 	 * This method performs a modular multiplication and stores the result in r: r = a.b mod m
 	 * The calculus based on the following formula: (a+b)^2 - (a-b)^2 = 4.a.b mod m
 	 * Requires: a.length == b.length == m.length == r.length == aux.length.
 	 * 			 rsaCipher must be an instance of Cipher implementing the Cipher.ALG_RSA_NOPAD algorithm.
 	 * 				and initialized with the modulus m and the exponent 2.
 	 * 			 r and aux must be transient memory.
 	 * Supports parameters overlapping (a == r or b == r).
 	 * @param a
 	 * @param b
 	 * @param m
 	 * @param r
 	 * @param aux auxiliary array to store intermediate results. At the end it contains (a+b)^2 mod m. 
 	 * @param rsaCipher Cipher instance to perform the square function.
 	 */
	public static void modMult(byte[] a, byte[] b, byte[] m, byte[] r, byte[] aux, Cipher rsaCipher)  
	{			
		byte[] aboveValue, belowValue;
		if(compareArrays(a, b) > 0)
		{
			aboveValue = a;
			belowValue = b;
		}
		else 
		{
			aboveValue = b;
			belowValue = a;
		}
				
		// aux = (a+b)^2 mod m
		addMod(a, b, aux, m);
		rsaCipher.doFinal(aux, (short)0, (short)aux.length, aux, (short)0);
		
		// r = (a-b)^2 mod m
		subtract(aboveValue, belowValue, r); 
		rsaCipher.doFinal(r, (short)0, (short)r.length, r, (short)0);
		
		// r = aux - r = 4.a.b mod m
		subtractMod(aux, r, r, m);
		
		//r = r/4 = 4.a.b/4 = a.b mod m 
		divideBy4Mod(r, m);
	}

}

