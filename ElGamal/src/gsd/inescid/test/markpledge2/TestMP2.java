package gsd.inescid.test.markpledge2;

import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.crypto.ElGamalKeyFactory;
import gsd.inescid.crypto.ElGamalKeyPair;
import gsd.inescid.crypto.ElGamalKeyParameters;
import gsd.inescid.crypto.ElGamalPrivateKey;
import gsd.inescid.crypto.ElGamalPublicKey;
import gsd.inescid.crypto.ElGamalVerifiableEncryption;
import gsd.inescid.crypto.util.CryptoUtil;
import gsd.inescid.markpledge2.MP2CandidateVote;
import gsd.inescid.markpledge2.MP2ElGamalKeyParameters;
import gsd.inescid.markpledge2.MP2Parameters;
import gsd.inescid.markpledge2.MP2Util;
import gsd.inescid.markpledge3.MP3Parameters;
import gsd.inescid.math.algebra.matrix.MatrixUtil;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public class TestMP2 {

	public static void main(String[] args) throws GeneralSecurityException
	{	
		//test1();
		//test2();
		test3();
	}
	
	public static Object[] getStaticarameters_1024_Q160_L24()
	{
		ElGamalKeyParameters keyParameters; 
		ElGamalKeyPair keyPair;
		ElGamalPublicKey kpub;
		ElGamalPrivateKey kpri;
		MP2Parameters mp2Param;
		
		// p=1024, q=160, lambda=24
		keyParameters = new ElGamalKeyParameters(
				new BigInteger("105758999053805277898585591608007470336107479487979435915705859496837108925900236708214548417943141985909692832982974446911807102304164206926640441799342782716587248940684708663447734733664891347515445809092618145002383785250590831060642705545287624985213449479106549964746120532626213045273715847379318387677"),
				new BigInteger("1004950598214686213714961911911155700240519795601"),
				new BigInteger("78316547078230389363119920985696339470334058340655395379177409940632162989550193512390255056068884961289995515105291614253755092847879805127421392624914412186865111460643436446007507414662678471692074408239131298318480353030573521740564463351193139101124321710668692860879315875812922758254730818918824117536"));
	
		kpub = new ElGamalPublicKey(keyParameters,
				new BigInteger("12662328332877509492426315871348516070328338612165133160047719572496216803579522211943154836294819499464370719154484483007937820047515290923729126383305239510741582867136887973305902422722004854305972886907092933662624832369113575733512822554057141763425178268257564917220931795668311825643790574793141838568"));
	
		kpri = new ElGamalPrivateKey(keyParameters, new BigInteger("172633943819395449210456695780797555472154117680"));
	
		keyPair = new ElGamalKeyPair(kpub,kpri);
		BigInteger [][] SO2qGenerator = new BigInteger[][]{
				{new BigInteger("10061194250051710209592604369561124461399978299"),
				 new BigInteger("625085705943092315963988948495644639478597308987")},
				{new BigInteger("379864892271593897750972963415511060761922486614"),
				 new BigInteger("10061194250051710209592604369561124461399978299")}
		};
		
		BigInteger SO2qOrder = new BigInteger("1004950598214686213714961911911155700240519795600");
		BigInteger fourMultiplier = new BigInteger("15607789403058690249745633516543450187435");
		BigInteger lambda = new BigInteger("16096940");
		
		mp2Param = new MP2Parameters(SO2qGenerator, SO2qOrder, fourMultiplier, lambda, kpub);
		
		return new Object[]{keyPair, mp2Param};
		
	}
	
	public static MP2ElGamalKeyParameters getParameters()
	{
		MP2ElGamalKeyParameters param = null;
		int i=0;
		do
		{
			i++;
			System.out.println("Create MP2 parameters try:" + i + " ...");
			try{
				param = new MP2ElGamalKeyParameters(1024, 160, 24, new SecureRandom(), null);
			} catch (GeneralSecurityException e)
			{
				System.out.println("\nFAIL\n");
			}
		} while (param == null);
		System.out.println("\nSUCCESS\n");
		return param;
	}
	
	public static void test3() throws GeneralSecurityException
	{
		MP2ElGamalKeyParameters keyParam = getParameters();
		ElGamalKeyPair kp = ElGamalKeyFactory.createKeyPair(keyParam.getElGamalKeyParameters(), null); 
		MP2Parameters param = new MP2Parameters(keyParam, kp.publicKey);
		
		BigInteger chal = CryptoUtil.generateRandomNumber(param.LAMBDA,new SecureRandom());
		
		//YESvote test
		MP2CandidateVote yesVote = MP2CandidateVote.getMP2CandidateVote(true, param);
		yesVote.createVerificationProof(chal, param);
		boolean v = MP2CandidateVote.verifyVectorEncryption(yesVote, param, chal,null);
		System.out.println("YESvote verification: " + v);

		
		//NOvote test
		MP2CandidateVote noVote = MP2CandidateVote.getMP2CandidateVote(false, param);
		noVote.createVerificationProof(chal, param);
		v = MP2CandidateVote.verifyVectorEncryption(noVote, param, chal, null);
		System.out.println("NOvote verification: " + v);
	}
	
	
	public static void test2() throws GeneralSecurityException
	{
		MP2ElGamalKeyParameters keyParam = getParameters();
		ElGamalKeyPair kp = ElGamalKeyFactory.createKeyPair(keyParam.getElGamalKeyParameters(), null); 
		ElGamalPublicKey kpub = kp.publicKey;
		MP2Parameters param = new MP2Parameters(keyParam, kp.publicKey);
		
		
		boolean verify = true;
		System.out.println("SO2qOrder:" + param.SO2Q_ORDER);
		System.out.println("Lambda   :" + param.LAMBDA);
		BigInteger dotProduct=BigInteger.ONE;
		int repeat = 100;

		do{
			BigInteger chal = CryptoUtil.generateRandomNumber(param.LAMBDA,new SecureRandom());
			BigInteger one = CryptoUtil.generateRandomNumber(param.LAMBDA,new SecureRandom());
			BigInteger zero = chal.subtract(one).mod(param.LAMBDA);
			//BigInteger zero = CryptoUtil.generateRandomNumber(param.lambda,new SecureRandom());
			//BigInteger one = chal.subtract(zero).mod(param.lambda);
					

			if(chal.compareTo(BigInteger.ZERO) <= 0 ||
					one.compareTo(BigInteger.ZERO) <= 0 ||
					zero.compareTo(BigInteger.ZERO) <= 0)
			{	
				System.out.println("NOP1");
			}

			System.out.println("C:" + chal);
			System.out.println("K:" + one);
			System.out.println("L:" + zero);
		
			long start = System.currentTimeMillis();
			BigInteger[] chalVector = param.getTestVector(chal);
			BigInteger[] oneVector = param.getYesVector(one);
			BigInteger[] zeroVector = param.getNoVector(zero);
			long end = System.currentTimeMillis();
			System.out.println("Time: " + (end - start));
			
			
			//oneVector = zeroVector; // NOvote
			
			BigInteger[] subtraction = MP2Util.vectorSubtraction(oneVector, zeroVector, kpub.q);
			dotProduct = MP2Util.vectorDotProduct(subtraction, chalVector, kpub.q);
			System.out.println(" SubVector: " + MatrixUtil.toString(subtraction));
			System.out.println("DotProduct: " + dotProduct);
			
			
			//Encrypt vector
			ElGamalVerifiableEncryption	vectorEncryption[] = new ElGamalVerifiableEncryption[2];
			vectorEncryption[0] = kpub.exponentialVerifiableEncrypt(oneVector[0]);
			vectorEncryption[1] = kpub.exponentialVerifiableEncrypt(oneVector[1]);
			
			ElGamalEncryption[] vectorEnc = new ElGamalEncryption[]{vectorEncryption[0].MESSAGE_ENCRYPTION,
																	vectorEncryption[1].MESSAGE_ENCRYPTION};
			ElGamalEncryption[] subEnc = MP2Util.vectorSubtraction(vectorEnc, zeroVector, kpub.p, kpub.q, kpub.g);
			
			ElGamalEncryption dotProductEnc = MP2Util.vectorDotProduct(subEnc, chalVector, kpub.p);
			
			if(verify)
			{
				BigInteger x = kpub.g.modPow(subtraction[0], kpub.p);
				BigInteger y = kpub.g.modPow(subtraction[1], kpub.p);
				System.out.println(" x:" + x);
				System.out.println(" y:" + y);
				System.out.println("ex:" + kp.privateKey.decryptQOrderMessage(subEnc[0]));
				System.out.println("ey:" + kp.privateKey.decryptQOrderMessage(subEnc[1]));
				
				BigInteger d = kpub.g.modPow(dotProduct, kpub.p);
				System.out.println(" d:" + d);
				System.out.println("ed:" + kp.privateKey.decryptQOrderMessage(dotProductEnc));
				
				/* create verification factor */
				BigInteger vFactorX = vectorEncryption[0].ENCRYPTION_FACTOR.multiply(chalVector[0]);
				BigInteger vFactorY = vectorEncryption[1].ENCRYPTION_FACTOR.multiply(chalVector[1]);
				BigInteger vFactor = vFactorX.add(vFactorY).mod(kpub.q);
				ElGamalVerifiableEncryption vEnc = new ElGamalVerifiableEncryption(dotProductEnc, vFactor);
				boolean test = kpub.verifyQOrderMessageEncryption(BigInteger.ONE, vEnc);
				System.out.println("verify? " + test);
				
				if(!test)
				{
					System.out.println("NOP - VERIFICATION FAILURE");
					return;
				}
			}
			
			
			if(!dotProduct.equals(BigInteger.ZERO))
			{
				System.out.println("NOP");
				System.out.println("\n--------------\n" + MatrixUtil.toString(param.SO2Q_GENERATOR));
			}
			repeat--;
			System.out.println("REPEAT: " + repeat);
		}while (dotProduct.equals(BigInteger.ZERO) && repeat > 0);
	}
	
	
	
	
	
	
	public static void test1() throws GeneralSecurityException
	{
		MP2ElGamalKeyParameters keyParam = getParameters();
		ElGamalKeyPair kp = ElGamalKeyFactory.createKeyPair(keyParam.getElGamalKeyParameters(), null); 
		ElGamalPublicKey kpub = kp.publicKey;
		MP2Parameters param = new MP2Parameters(keyParam, kp.publicKey);

		System.out.println("SO2qOrder:" + param.SO2Q_ORDER);
		System.out.println("Lambda   :" + param.LAMBDA);
		BigInteger dotProduct=BigInteger.ONE;
		int repeat = 10;

		do{
			BigInteger chal = CryptoUtil.generateRandomNumber(param.LAMBDA,new SecureRandom());
			BigInteger one = CryptoUtil.generateRandomNumber(param.LAMBDA,new SecureRandom());
			BigInteger zero = chal.subtract(one).mod(param.LAMBDA);
			//BigInteger zero = CryptoUtil.generateRandomNumber(param.lambda,new SecureRandom());
			//BigInteger one = chal.subtract(zero).mod(param.lambda);


			if(chal.compareTo(BigInteger.ZERO) <= 0 ||
					one.compareTo(BigInteger.ZERO) <= 0 ||
					zero.compareTo(BigInteger.ZERO) <= 0)
			{	
				System.out.println("NOP1");
			}

			System.out.println("C:" + chal);
			System.out.println("K:" + one);
			System.out.println("L:" + zero);
		
			long start = System.currentTimeMillis();
			BigInteger[] chalVector = param.getTestVector(chal);
			BigInteger[] oneVector = param.getYesVector(one);
			BigInteger[] zeroVector = param.getNoVector(zero);
			long end = System.currentTimeMillis();
			System.out.println("Time: " + (end - start));
			
			BigInteger[] subtraction = MP2Util.vectorSubtraction(oneVector, zeroVector, kpub.q);
			dotProduct = MP2Util.vectorDotProduct(subtraction, chalVector, kpub.q);
			System.out.println(" SubVector: " + MatrixUtil.toString(subtraction));
			System.out.println("DotProduct: " + dotProduct);
			if(!dotProduct.equals(BigInteger.ZERO))
			{
				System.out.println("NOP");
				System.out.println("\n--------------\n" + MatrixUtil.toString(param.SO2Q_GENERATOR));
			}
			repeat--;
			System.out.println("REPEAT: " + repeat);
		}while (dotProduct.equals(BigInteger.ZERO) && repeat > 0);
	}
	
	
}
