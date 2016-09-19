package gsd.inescid.test.markpledgeperformance;

import gsd.inescid.crypto.ElGamalKeyFactory;
import gsd.inescid.crypto.ElGamalKeyPair;
import gsd.inescid.crypto.ElGamalKeyParameters;
import gsd.inescid.crypto.ElGamalPublicKey;
import gsd.inescid.markpledge2.MP2ElGamalKeyParameters;
import gsd.inescid.math.algebra.matrix.MatrixUtil;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;


public class PerformanceTest {

	public static void main(String[] args) throws GeneralSecurityException
	{
		
		MP2ElGamalKeyParameters param = new MP2ElGamalKeyParameters(1024, 160, 24,  null, null);
		ElGamalKeyParameters kparam = new ElGamalKeyParameters(param.p, param.q, param.g);
		
		
		System.out.println(param + "\n");
		System.out.println(kparam + "\n\n");
		
		ElGamalKeyPair kp = ElGamalKeyFactory.createKeyPair(kparam, new SecureRandom());
				
		// MP3 constant g^-1 parameter
		BigInteger gInv = param.g.modPow(param.q.subtract(BigInteger.ONE), param.p);
		System.out.println("g^-1: " + gInv);
		
		testRandomElementEncryption(param, kp.publicKey, gInv);
	
	}
	
	
	public static void testRandomElementEncryption(MP2ElGamalKeyParameters param, ElGamalPublicKey kpub, BigInteger gInv) throws InvalidAlgorithmParameterException
	{
		
		
		for(int repeat=10; repeat>0; repeat--)
		{
			BigInteger randomE = (new BigInteger(param.q.bitLength(), new SecureRandom())).mod(param.q);
			BigInteger randomEncryptionFactor1 = (new BigInteger(param.q.bitLength(), new SecureRandom())).mod(param.q);			
			BigInteger randomEncryptionFactor2 = (new BigInteger(param.q.bitLength(), new SecureRandom())).mod(param.q);
			
			BigInteger[][] matrixPower;
			long start, stop1, stop2, stop3, end;

			System.out.println("\n\n########################################\nRandom value: " + randomE);
		
			
			/******** MARKPLEDGE 3 ********/
			// 1 - common encryption of random value
			start = System.currentTimeMillis();
			// 1.1 - prepare exponential message for encryption
			BigInteger bigIntExp = param.g.modPow(randomE, param.p);
			stop1 = System.currentTimeMillis();
			// 1.2 - encrypt exponential message
			kpub.encryptQOrderMessage(bigIntExp, randomEncryptionFactor1);
			stop2 = System.currentTimeMillis();
			
			// 2 - YES vote commitment
			kpub.encryptQOrderMessage(param.g, randomEncryptionFactor2);
			stop3 = System.currentTimeMillis();
			
			// 3 - NO vote commitment
			kpub.encryptQOrderMessage(gInv, randomEncryptionFactor2);
			end = System.currentTimeMillis();
			
			long randomValuePreparationTime = stop1 - start;
			long randomValueEncryptionTime = stop2 - stop1;
			long totalRandomValueEncryptionTime = stop2 - start;
			long yesVoteEncryptionTime = stop3 - stop2;
			long noVoteEncryptionTime = end - stop3;
			long yesVoteTotalTime = totalRandomValueEncryptionTime + yesVoteEncryptionTime;
			long noVoteTotalTime = totalRandomValueEncryptionTime + noVoteEncryptionTime;
			
			System.out.println("----------------------");
			System.out.println("MP3 random value preparation time:" + randomValuePreparationTime);
			System.out.println("MP3 random value encryption time:" + randomValueEncryptionTime);
			System.out.println("MP3 random value total time:" + totalRandomValueEncryptionTime);
			System.out.println("MP3 YES vote encryption time:" + yesVoteEncryptionTime);
			System.out.println("MP3 YES vote total time:" + yesVoteTotalTime);
			System.out.println("MP3 NO vote encryption time:" + noVoteEncryptionTime);
			System.out.println("MP3 NO vote total time:" + noVoteTotalTime);
			
			
			
			/******** MARKPLEDGE 2 ********/
			// MARKPLEDGE 2 (normal recursive exponentiation)
			start = System.currentTimeMillis();
			// 1 - create random SO(2,q) element
			matrixPower = MatrixUtil.rModPow(param.SO2qGenerator, randomE, param.q);
			stop1 = System.currentTimeMillis();
			// 2 - encrypt vector
			// 2.1 - prepare exponential representation of vector components
			BigInteger a = param.g.modPow(matrixPower[0][0], param.p);
			BigInteger b = param.g.modPow(matrixPower[0][1], param.p);
			// 2.2 encrypt exponential vector components
			kpub.encryptQOrderMessage(a, randomEncryptionFactor1);
			kpub.encryptQOrderMessage(b, randomEncryptionFactor2);
			end = System.currentTimeMillis();
			
			long matrixExponentiationTime = stop1 - start;
			long totalVectorEncryptionTime = end - stop1;
			long totalMP2Time = matrixExponentiationTime + totalVectorEncryptionTime;
			
			System.out.println("----------------------");
			System.out.println("MP2 SO(2,q) exponentiation");
			System.out.println("MP2 matrix exponentiation time:" + matrixExponentiationTime);
			System.out.println("MP2 vector encryption time:" + totalVectorEncryptionTime);
			System.out.println("MP2 total time:" + totalMP2Time);
			
			
			// MARKPLEDGE 2 (SO(2,q) recursive exponentiation)
			start = System.currentTimeMillis();
			// 1 - create random SO(2,q) element
			matrixPower = MatrixUtil.rSO2qModPow(param.SO2qGenerator, randomE, param.q);
			stop1 = System.currentTimeMillis();
			// 2 - encrypt vector
			// 2.1 - prepare exponential representation of vector components
			a = param.g.modPow(matrixPower[0][0], param.p);
			b = param.g.modPow(matrixPower[0][1], param.p);
			// 2.2 encrypt exponential vector components
			kpub.encryptQOrderMessage(a, randomEncryptionFactor1);
			kpub.encryptQOrderMessage(b, randomEncryptionFactor2);
			end = System.currentTimeMillis();
			
			matrixExponentiationTime = stop1 - start;
			totalVectorEncryptionTime = end - stop1;
			totalMP2Time = matrixExponentiationTime + totalVectorEncryptionTime;
			
			System.out.println("----------------------");
			System.out.println("MP2 normal exponentiation");
			System.out.println("MP2 matrix exponentiation time:" + matrixExponentiationTime);
			System.out.println("MP2 vector encryption time:" + totalVectorEncryptionTime);
			System.out.println("MP2 total time:" + totalMP2Time);
			
		}
	}
	
}
