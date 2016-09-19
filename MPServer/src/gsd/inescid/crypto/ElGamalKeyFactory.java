package gsd.inescid.crypto;

import gsd.inescid.crypto.util.CryptoUtil;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class ElGamalKeyFactory {
	
	
	/**
	 * Creates a new ElGamal parameters and key pair.
	 * The private key is a value in the range [2,q-1] and the public key is a value in the range [2,p-1].
	 * The private key is selected randomly.
	 * 
	 * @param modulusSize modulus length in bits
	 * @param keySize size of parameter q and maximum private key length in bits 
	 * @param random randomness source to be used in the key creation.
	 * @param hashFunction the name of the hash function to use in the key parameters generation.
	 * @return new ElGamal key pair
	 * @throws InvalidParameterException If parameter random or hashFunction is null. 
	 * @throws GeneralSecurityException If the key parameters cannot be created.
	 * @throws NoSuchAlgorithmException if there is no provider for the selected hashFunction.
	 */
	public static final ElGamalKeyPair createKeyPair(int modulusSize, int keySize, Random random, String hashFunction) throws GeneralSecurityException
	{
		if (random == null) throw new InvalidParameterException("Null random source.");
		if (hashFunction == null) throw new InvalidParameterException("Null hashFunction");
		
		ElGamalKeyParameters param = new ElGamalKeyParameters(modulusSize, keySize, random, hashFunction);
		return createKeyPair(param, random);
	}
	
	/**
	 * Creates a new ElGamal parameters and key pair.
	 * The private key is a value in the range [2,q-1] and the public key is a value in the range [2,p-1].
	 * The private key is selected randomly.
	 * 
	 * It is used the default SecureRandom for the randomness source of the private key 
	 * and the default random source and hash function for the key parameters generation
	 * (defined in ElGamalKeyParameters).
	 * 
	 * @param modulusSize modulus length in bits
	 * @param keySize size of parameter q and maximum private key length in bits 
	 * @return new ElGamal key pair
	 * @throws GeneralSecurityException If the key parameters cannot be created.
	 */
	public static final ElGamalKeyPair createKeyPair(int modulusSize, int keySize) throws GeneralSecurityException
	{
		ElGamalKeyParameters param = new ElGamalKeyParameters(modulusSize, keySize, null, null);
		return createKeyPair(param, null);
	}
	
	
	/**
	 * Creates a new ElGamal key pair for the given key parameters.
	 * The private key is a value in the range [2,q-1] and the public key is a value in the range [2,p-1].
	 * The private key is selected randomly.
	 *  
	 * @param param the key parameters
	 * @param random randomness source to be used in the key creation. 
	 * 				 If null the default SecureRandom is used.
	 * @return new ElGamal key pair
	 */
	public static final ElGamalKeyPair createKeyPair(ElGamalKeyParameters param, Random random)
	{
		if (random == null)
			random = new SecureRandom();
	
		BigInteger x = CryptoUtil.generateRandomNumber(param.q.subtract(BigInteger.valueOf(2)), random);
		x = x.add(BigInteger.valueOf(2));
		ElGamalPublicKey kpub = new ElGamalPublicKey(param, param.g.modPow(x, param.p));
		ElGamalPrivateKey kpri = new ElGamalPrivateKey(param, x);
		
		return new ElGamalKeyPair(kpub, kpri);
		
		
	}
	
	
	
}
