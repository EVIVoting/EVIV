package gsd.inescid.math.algebra.matrix;

import gsd.inescid.crypto.util.CryptoUtil;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.util.Random;

public class TestMatrix {

	public static void main(String[] args) throws InvalidAlgorithmParameterException
	{
		Random r = new Random();
		long start, end, total;
		int pLength = 1024;
		int qLength = 160;
		int loopCount = 100000;
		
		BigInteger modulus = BigInteger.probablePrime(qLength, r);
		
		Matrix mr;
		BigInteger[][] mb;
		
		
		total = 0;
		for(int i=0; i<loopCount; i++)
		{
			Matrix a = Matrix.getRandomSO2QMatrix(modulus);
			BigInteger exponent = CryptoUtil.generateRandomNumber(modulus, r);
			//exponent = new BigInteger("7895");
			
			Matrix ma = a.clone();
			
			start = System.nanoTime();
			mr = MatrixUtil.matrixModExpSO2Q(ma, exponent, modulus);
			end = System.nanoTime();
		
			total += end-start;
			//System.out.println(mr);
			
		}
		System.out.println("T1: " + total/loopCount);
		
		total = 0;
		for(int i=0; i<loopCount; i++)
		{
			Matrix a = Matrix.getRandomSO2QMatrix(modulus);
			BigInteger exponent = CryptoUtil.generateRandomNumber(modulus, r);
			//exponent = new BigInteger("7895");
			
			Matrix ma = a.clone();
			
			start = System.nanoTime();
			mr = MatrixUtil.matrixModExpT(ma, exponent, modulus);
			end = System.nanoTime();
		
			total += end-start;
			//System.out.println(mr);
			
		}
		System.out.println("T1.1: " + total/loopCount);
		
		total = 0;
		for(int i=0; i<loopCount; i++)
		{
			Matrix a = Matrix.getRandomSO2QMatrix(modulus);
			BigInteger exponent = CryptoUtil.generateRandomNumber(modulus, r);
			mb = a.toArray();
			
			start = System.nanoTime();
			mb = MatrixUtil.rSO2qModPow(mb, exponent, modulus);
			end = System.nanoTime();	
			total += end-start;
			
			mr = Matrix.fromArray(mb);
			//System.out.println(mr);
			
		}
		System.out.println("T2: " + total/loopCount);
	
		
		BigInteger modulusP = BigInteger.probablePrime(pLength, r);
		BigInteger res;
		total = 0;
		for(int i=0; i<loopCount; i++)
		{
			BigInteger exponent = CryptoUtil.generateRandomNumber(modulus, r);
			BigInteger base = CryptoUtil.generateRandomNumber(modulus, r);
			
			start = System.nanoTime();
			res = base.modPow(exponent, modulusP);
			end = System.nanoTime();
		
			total += end-start;
			//System.out.println(res.toString(16));
		}
		System.out.println("T3: " + total/loopCount);
	}
}
