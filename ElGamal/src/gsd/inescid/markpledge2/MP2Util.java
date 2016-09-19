package gsd.inescid.markpledge2;

import gsd.inescid.crypto.ElGamalEncryption;

import java.math.BigInteger;

public class MP2Util {
	/* VECTOR UTILITY FUNCTIONS */

	
	
	public static BigInteger[] vectorSubtraction(BigInteger[] v1, BigInteger[] v2, BigInteger modulus)
	{
		BigInteger[] sub = new BigInteger[]{v1[0].subtract(v2[0]), v1[1].subtract(v2[1])};
		sub[0] = sub[0].mod(modulus);
		sub[1] = sub[1].mod(modulus);
		return sub;
	}
	
	public static BigInteger vectorDotProduct(BigInteger[] v1, BigInteger[] v2, BigInteger modulus)
	{
		BigInteger m1 = v1[0].multiply(v2[0]);
		BigInteger m2 = v1[1].multiply(v2[1]);
		BigInteger dotProduct = (m1.add(m2)).mod(modulus);
		return dotProduct;
	}
	
	
	public static ElGamalEncryption[] vectorSubtraction(ElGamalEncryption[] v1, BigInteger[] v2, BigInteger p, BigInteger q, BigInteger g)
	{
		BigInteger[] sub = new BigInteger[]{g.modPow(q.subtract(v2[0]), p), g.modPow(q.subtract(v2[1]), p)};
		
		ElGamalEncryption subEnc[] = new ElGamalEncryption[2];
		subEnc[0] = new ElGamalEncryption(v1[0].X, v1[0].Y.multiply(sub[0]).mod(p));
		subEnc[1] = new ElGamalEncryption(v1[1].X, v1[1].Y.multiply(sub[1]).mod(p));
		return subEnc;
	}
	
	
	public static ElGamalEncryption vectorDotProduct(ElGamalEncryption[] v1, BigInteger[] v2, BigInteger p)
	{
		ElGamalEncryption x = multiplyByClearTextValue(v1[0], v2[0], p);  
		ElGamalEncryption y = multiplyByClearTextValue(v1[1], v2[1], p);
		ElGamalEncryption r = x.multiply(y, p);
		return r;
	}
	
	public static ElGamalEncryption multiplyByClearTextValue(ElGamalEncryption enc, BigInteger v, BigInteger p)
	{
		BigInteger x = enc.X.modPow(v, p);
		BigInteger y = enc.Y.modPow(v, p);
		ElGamalEncryption r = new ElGamalEncryption(x,y);
		return r;
	}
}
