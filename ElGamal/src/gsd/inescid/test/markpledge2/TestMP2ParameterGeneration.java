package gsd.inescid.test.markpledge2;

import gsd.inescid.markpledge2.MP2ElGamalKeyParameters;
import gsd.inescid.math.algebra.matrix.MatrixUtil;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;


public class TestMP2ParameterGeneration {

	public static void main(String[] args) throws GeneralSecurityException
	{
		
		MP2ElGamalKeyParameters param = new MP2ElGamalKeyParameters(1024, 160 , 24, null, null);
		
		System.out.println(param);
		//testQOrderGenerator(param);
		//testSO2qOrderGenerator(param);
		testMatrixExponentiation(param);
	
	}
	
	
	
	
	public static void testMatrixExponentiation(MP2ElGamalKeyParameters param) throws GeneralSecurityException
	{
		
		long total = 0;
		int samples = 100;
		SecureRandom r = new SecureRandom();
		for(int repeat=samples; repeat>0; repeat--)
		{
			BigInteger randomE = new BigInteger(param.q.bitLength(), new SecureRandom());
			BigInteger[][] matrixPower;
			long start, end;
			
			//param = new MP2ElGamalKeyParameters(1024, 160 , r, null);
			
			//System.out.println("\n\n########################################\nRandom exponent: " + randomE);
		
			/*
			start = System.currentTimeMillis();
			matrixPower = MatrixUtil.matrixModPow(param.SO2qGenerator, randomE, param.q);
			end = System.currentTimeMillis();
			System.out.println("----------------------\nmatrixModPow time: " + (end-start));
			System.out.println(MatrixUtil.toString(matrixPower));
			 */

			/*
			start = System.currentTimeMillis();
			matrixPower = MatrixUtil.SO2qModPow(param.SO2qGenerator, randomE, param.q);
			end = System.currentTimeMillis();
			System.out.println("----------------------\nSO2qModPow time: " + (end-start));
			System.out.println(MatrixUtil.toString(matrixPower));
			 */
			/*
			start = System.currentTimeMillis();
			matrixPower = MatrixUtil.rModPow(param.SO2qGenerator, randomE, param.q);
			end = System.currentTimeMillis();
			//System.out.println("----------------------\nrModPow time: " + (end-start));
			//System.out.println(MatrixUtil.toString(matrixPower));
			*/
			
			start = System.currentTimeMillis();
			matrixPower = MatrixUtil.rSO2qModPow(param.SO2qGenerator, randomE, param.q);
			end = System.currentTimeMillis();
			/*System.out.println("----------------------\nrSO2qModPow time: " + (end-start));
			System.out.println(MatrixUtil.toString(matrixPower));
			
			start = System.currentTimeMillis();
			BigInteger bigIntExp = param.g.modPow(randomE, param.q);
			end = System.currentTimeMillis();
			System.out.println("----------------------\nBigInteger.modPow time: " + (end-start));
			System.out.println(bigIntExp);
		*/
			total += end-start;
			
		}
		System.out.println("Matrix time (" + samples + " samples) = " + total/samples);
		
	}
	
	
	public static void testQOrderGenerator(MP2ElGamalKeyParameters param)
	{
		System.out.println("Test generator order...");
		
		BigInteger exponent = BigInteger.ZERO;
		BigInteger r;
		do {
			exponent = exponent.add(BigInteger.ONE);
			r = param.g.modPow(exponent, param.p);
			System.out.println("" + exponent + " - " + r);
		} while(r.compareTo(BigInteger.ONE) != 0);
		
		if(exponent.compareTo(param.q)==0)
			System.out.println("Parameters VALIDATED!");
		else
			System.out.println("INVALID parameters!");
	}
	
	public static void testSO2qOrderGenerator(MP2ElGamalKeyParameters param) throws InvalidAlgorithmParameterException
	{
		System.out.println("Test generator order...");
		
		BigInteger exponent = BigInteger.ZERO;
		BigInteger[][] r;
		do {
			exponent = exponent.add(BigInteger.ONE);
			r = MatrixUtil.matrixModPow(param.SO2qGenerator, exponent, param.q);
			System.out.println("" + exponent + " ------------------------\n " + MatrixUtil.toString(r));
			r = MatrixUtil.SO2qModPow(param.SO2qGenerator, exponent, param.q); 
			System.out.println("SO2qModPOW\n" + MatrixUtil.toString(r));
			
		} while(exponent.compareTo(param.q)<=0);
		//} while(exponent.compareTo(BigInteger.valueOf(30))<=0);
				
	}
}
