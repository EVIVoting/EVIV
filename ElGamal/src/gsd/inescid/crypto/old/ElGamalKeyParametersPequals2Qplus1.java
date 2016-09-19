package gsd.inescid.crypto.old;

import java.math.BigInteger;
import java.util.Random;
import java.security.InvalidParameterException;

/**
 * Immutable class ElGamalKeyParameters
 * @author Rui Joaquim
 *
 */
public final class ElGamalKeyParametersPequals2Qplus1 {

	public static final int MINIMUM_KEY_SIZE = 5;
	public static final int TO_STRING_RADIX = 10;
	
	public final BigInteger p; // a "safe prime" that defines the "encryption group" Z*_p, such that p = 2q + 1
	public final BigInteger q; 
	public final BigInteger g; // generator of G_q, a q-order subgroup of Z*_p that defines the message space
	
	private static final BigInteger ONE = BigInteger.ONE;
	public static final BigInteger TWO = new BigInteger("2"); //public because it is not available in the BigInteger class
	
	
	/**
	 * Create key parameters from the given parameters.
	 * @param p safe prime p = 2*q + 1
	 * @param q prime number q which defines the order of the generator g
	 * @param g generator of a q-order subgroup of Z*_p
	 * @throws InvalidParameterException if parameters do not match the specifications
	 */
	public ElGamalKeyParametersPequals2Qplus1(BigInteger p, BigInteger q, BigInteger g)
	{
		if (p.compareTo(q.multiply(TWO).add(ONE))!=0) throw new InvalidParameterException("p != 2*q + 1");
		if (!p.isProbablePrime(100)) throw new InvalidParameterException("p is not prime");
		if (!q.isProbablePrime(100)) throw new InvalidParameterException("q is not prime");
	
		this.p = p;
		this.q = q;
		this.g = g;
			
		//verify if k (g=k^2) is a generator of Z*_p, if so g is a generator of a q order subgroup of Z*_p
		BigInteger k = getZpGenerator();
			
		//verify if k is a generator of Z*_p
		if( k.modPow(TWO, p).compareTo(ONE)==0 || k.modPow(q, p).compareTo(ONE)==0)
			throw new InvalidParameterException("g is not a q-order generator of Z*_p");
	
		
	}
	

	
	/**
	 * Create key parameters for the requested key size.
	 * @param keySize maximum supported key size in bits (defines the length of q) 
	 * @param random randomness source
	 * @throws InvalidParameterException if keySize < MINIMUM_KEY_SIZE8.
	 */
	public ElGamalKeyParametersPequals2Qplus1(int keySize, Random r)
	{
		if (keySize < MINIMUM_KEY_SIZE) throw new InvalidParameterException("keySize must be >= MINIMUM_KEY_SIZE");
		
		BigInteger[] pq = createPQ(keySize, r);
		this.p = pq[0];
		this.q = pq[1];
		this.g = getQOrderGenerator(ONE);
	}
	
	
	/**
	 * Create key parameters for the requested key size.
	 * @param keySize maximum supported key size in bits (defines the length of q)
	 * @param baseZpGeneratorSearch defines the value used to start the search for a generator of Z_p which is then used to set g, the Z*_q generator   
	 * @param random randomness source
	 * @throws InvalidParameterException if keySize < MINIMUM_KEY_SIZE, or baseZpGenerator length >= keySize.
	 */
	public ElGamalKeyParametersPequals2Qplus1(int keySize, BigInteger baseZpGeneratorSearch, Random r)
	{
		if (keySize < MINIMUM_KEY_SIZE) throw new InvalidParameterException("keySize must be >= MINIMUM_KEY_SIZE");
		if (keySize <= baseZpGeneratorSearch.bitLength()) throw new InvalidParameterException("baseZpGenerator length must be < keySize");
		
		BigInteger[] pq = createPQ(keySize, r);
		this.p = pq[0];
		this.q = pq[1];
		this.g = getQOrderGenerator(baseZpGeneratorSearch);
	}

	
	/**
	 * Randomly creates the key parameters for a given keySize
	 * @param keySize maximum supported key size in bits (defines the length of q)
	 * @param random randomness source
	 * @return BigIntege[] with the p and q parameters
	 */
	private final static BigInteger[] createPQ(int keySize, Random random)
	{
		BigInteger p, q, pq[];
		while(true)
		{
			q = BigInteger.probablePrime(keySize, random);
			p = ONE.add(q.multiply(TWO));
			if (p.isProbablePrime(100))
			{
				pq = new BigInteger[2];
				pq[0] = p;
				pq[1] = q;
				return pq;
			}
		}
	}
	
	
	/**
	 * Create a q-order generator of Z*_p
	 * @param startSearch sets the start point for the initial Z*_p generator search  
	 * @return returns the first q-order generator ( > startSearch^2) of Z*_p
	 */
	public final BigInteger getQOrderGenerator(BigInteger startSearch)
	{
		BigInteger testValue = startSearch.add(ONE); 
		BigInteger lowLimit = TWO;
		BigInteger highLimit = this.p.subtract(TWO);
		while (true)
		{
			if(testValue.compareTo(lowLimit) < 0 || testValue.compareTo(highLimit) > 0) //If the search reaches p-2 it starts again from the value 2. 
				testValue = TWO;
			
			
			if(   testValue.modPow(TWO, this.p).compareTo(ONE)!=0 
			   && testValue.modPow(this.q, this.p).compareTo(ONE)!=0)
			{	
				BigInteger newGen = testValue.modPow(TWO, this.p);
				return newGen;
			}
			
			testValue = testValue.add(ONE);
		}
	}
	
	
	/**
	 * Get the generator of Z_p that originated g;
	 * @return k = squareRoot(this.g) a generator of Z_p 
	 */
	private final BigInteger getZpGenerator()
	{
		//k^(q+1) "mod p" = k, since we have g=k^2 it is necessary to calculate exp = (q+1)/2
		BigInteger exp = this.q.add(ONE).divide(TWO); 
		//(g=k^2)^exp = (k^2)^((q+1)/2) = k^(2*(q+1)/2) = k^(q+1) = k
		BigInteger k = this.g.modPow(exp, this.p); 
		//get k into Z*_q
		if(k.compareTo(this.q) > 0) 
			k=this.p.subtract(k);
		return k;
	}
	
	
	public final String toString(int radix)
	{
		String s = "p = " + this.p.toString(radix) + "\n"
				 + "q = " + this.q.toString(radix) + "\n"
				 + "g = " + this.g.toString(radix);
		return s;
	}
	
	public final String toString()
	{
		return toString(ElGamalKeyParametersPequals2Qplus1.TO_STRING_RADIX);
	}
	
	
}
