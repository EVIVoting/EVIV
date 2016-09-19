package gsd.inescid.math.algebra.matrix;

import gsd.inescid.crypto.util.CryptoUtil;

import java.math.BigInteger;
import java.util.Random;
/**
 * Matrix structure class
 * {a,b
 *  c,d}
 * 
 * @author Rui
 *
 */
public class Matrix {
	public BigInteger a;
	public BigInteger b;
	public BigInteger c;
	public BigInteger d;
	
	public Matrix()
	{
		this.a = BigInteger.ONE;
		this.b = BigInteger.ZERO;	
		this.c = BigInteger.ZERO;	
		this.d = BigInteger.ONE;	
	}
	
	public Matrix clone()
	{
		Matrix m = new Matrix();
		m.a = this.a;
		m.b = this.b;
		m.c = this.c;
		m.d = this.d;
	
		return m;
	}
	
	
	
	public BigInteger[][] toArray()
	{
		BigInteger[][] m = new BigInteger[2][2];
		m[0][0] = a;
		m[0][1] = b;
		m[1][0] = c;
		m[1][1] = d;
		
		return m;
	}
	
	public static Matrix fromArray(BigInteger[][] matrix)
	{
		Matrix m = new Matrix();
		m.a = matrix[0][0];
		m.b = matrix[0][1];
		m.c = matrix[1][0];
		m.d = matrix[1][1];
		
		return m;
	}
	
	public String toString(){return toString(16);}
	public String toString(int base)
	{
		return "[[ " + this.a.toString(base) + ", " + this.b.toString(base) + "]\n" +
			   " [ " + this.c.toString(base) + ", " + this.d.toString(base) + "]]";
	}
	
	
	public static Matrix getRandomMatrix(BigInteger maxValue)
	{
		Random r = new Random();
		Matrix m = new Matrix();
		
		m.a = CryptoUtil.generateRandomNumber(maxValue, r);
		m.b = CryptoUtil.generateRandomNumber(maxValue, r);
		m.c = CryptoUtil.generateRandomNumber(maxValue, r);
		m.d = CryptoUtil.generateRandomNumber(maxValue, r);
		
		return m;
	}
	
	public static Matrix getRandomSO2QMatrix(BigInteger modulus)
	{
		Random r = new Random();
		Matrix m = new Matrix();
		
		m.a = CryptoUtil.generateRandomNumber(modulus, r);
		m.b = CryptoUtil.generateRandomNumber(modulus, r);
		m.c = modulus.subtract(m.b);
		m.d = m.a;
		
		return m;
	}
}
