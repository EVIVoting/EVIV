package gsd.inescid.test.crypto;

import gsd.inescid.crypto.*;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Random;

public class ElGamalTest {
	
	public static ElGamalKeyPair staticTestKeyPair = null; //buildinitialStaticKey();
	public static ElGamalKeyParameters staticParameters = null; //buildinitialStaticKey();
	
	private static void buildinitialStaticKey()
	{
		staticParameters = new ElGamalKeyParameters(
				new BigInteger("99168425138929890354816708627596705375533093249828501736810565263717288960776102725953000828371314635733942222621055825581582080909432182978392950736578055136917417265049383635669239844702990275993721138024911621217253058887078522414095141908933215815394420298459928703860916923459361760264694281846366339153"),
				new BigInteger("72744281067160770168400117435343062461559905037429870814844993304309037826883"),
				new BigInteger("68984845177102815514738900132840289036399716306363647242945184096294261833610127385587226704052055172308521565983019209413627555526719534927522287575427747441573412187263128653511585606049603835245066498504850727455713172548517055384730361771644564136286396553878096073066856897210678470201858654779322782477"));
		ElGamalPublicKey kpub = new ElGamalPublicKey(staticParameters,
				new BigInteger("64236325294069710699091145689506396881089009995947501736111706440136116500289286141600634828592060729264250124067647281747812582080013549813433701846800855085380021050099330141207717216754670595360148566448259998637025956623029502865441552065799311431039867937854188412656683059784100558998832342860967761744"));
		ElGamalPrivateKey kpri = new ElGamalPrivateKey(staticParameters, kpub.q.subtract(new BigInteger("62036061978806689161167658378426293860581255099970920924941971214338304682292")));
		staticTestKeyPair = new ElGamalKeyPair(kpub,kpri);
	}
	
	public static void buildNewStaticKeyPair(int pSize, int qSize) throws GeneralSecurityException
	{
		long start, end;
		start = System.currentTimeMillis();
		staticParameters = new ElGamalKeyParameters(pSize, qSize, null, null);
		staticTestKeyPair = ElGamalKeyFactory.createKeyPair(staticParameters, null);
		end = System.currentTimeMillis();
		System.out.println("\nNew key pair in " + (end-start) + "ms\n");
	}
		
	
	/**
	 * @param args
	 * @throws GeneralSecurityException 
	 */
	public static void main(String[] args) throws GeneralSecurityException {
		int pSize = 1024;
		int qSize = 256;
		int messageBitLength = 250;
		boolean testGenerator = false;
		boolean printElements = false;
		boolean useStaticKey = true;
		boolean different2ndGenerator = true; //only works if useStaticKey = false
		
		if(useStaticKey)
			buildinitialStaticKey();
		
		//parametersTest(pSize, qSize, testGenerator, printElements);
		//keyFactoryTest(useStaticKey, different2ndGenerator, pSize, qSize);
		exponentiationTimeTest(useStaticKey, pSize, qSize, messageBitLength);

	}

	/* *************************************************************************
	 * Exponentiation Time Test
	 */
	public static void exponentiationTimeTest(boolean useStaticKey, int newPSize, int newQSize, int messageBitLength) throws GeneralSecurityException
	{
		Random r = new SecureRandom();
		int radix = ElGamalKeyParameters.TO_STRING_RADIX;
		long start, end;
		
		if(!useStaticKey)
			buildNewStaticKeyPair(newPSize, newQSize);
		
		ElGamalKeyPair kp = staticTestKeyPair;
		System.out.println("Key Pair:\n" + kp);
		ElGamalKeyParameters kparam = staticParameters;
		
		BigInteger m = new BigInteger(messageBitLength, r);
		System.out.println("\nOriginal message  : " + m.toString(radix));
		
		start = System.currentTimeMillis();
		BigInteger g_m = kparam.g.modPow(m, kparam.p);
		end = System.currentTimeMillis();
		System.out.println("g^m (" + (end-start) + "ms)\n" + g_m);
	}
	
	
	
	
	/* *************************************************************************
	 * 	KeyFactory Test
	 */
	public static void keyFactoryTest(boolean useStaticKey, boolean different2ndGenerator, int newPSize, int newQSize) throws GeneralSecurityException
	{
		Random r = new SecureRandom();
		int qSize = newQSize; 
		int radix = ElGamalKeyParameters.TO_STRING_RADIX;
		long start, end;
		
		if(!useStaticKey)
			buildNewStaticKeyPair(newPSize, newQSize);
		
		ElGamalKeyPair kp = staticTestKeyPair;
		System.out.println("Key Pair:\n" + kp);
		ElGamalKeyParameters kparam = staticParameters;
		
		//testParameters(kparam, true);
		
		/*************************************************************************/
		
		BigInteger m = new BigInteger(qSize-1, r);
		System.out.println("\nOriginal message  : " + m.toString(radix));
		
		start = System.currentTimeMillis();
		ElGamalVerifiableEncryption ve = kp.publicKey.encryptVerifiable(m);
		end = System.currentTimeMillis();
		System.out.println("Verifiable Encryption (" + (end-start) + "ms)\n" + ve);
		System.out.println("Auto verify : " + kp.publicKey.verifyMessageEncryption(m, ve));
		
		start = System.currentTimeMillis();
		BigInteger dm = kp.privateKey.decrypt(ve.MESSAGE_ENCRYPTION);
		end = System.currentTimeMillis();
		System.out.println("Message decyption (" + (end-start) + "ms): " + dm.toString(radix));
		
		/**********************************************************************/
		BigInteger newGen;
		if(different2ndGenerator && !useStaticKey)
			newGen = kparam.getQOrderGenerator(2);
		else 
			newGen = kparam.g;
		
		System.out.println("\nnewGen^1 : " + newGen);
		
		start = System.currentTimeMillis();
		ve = kp.publicKey.encryptVerifiableQOrderMessage(newGen);
		end = System.currentTimeMillis();
		System.out.println("newGen Verifiable Encryption (" + (end-start) + "ms)\n" + ve);
		System.out.println("Auto verify : " + kp.publicKey.verifyQOrderMessageEncryption(newGen, ve));
		start = System.currentTimeMillis();
		dm = kp.privateKey.decryptQOrderMessage(ve.MESSAGE_ENCRYPTION);
		end = System.currentTimeMillis();
		System.out.println("newGen decyption (" + (end-start) + "ms): " + dm.toString(radix));
		
		
		/****************************************************************************/
		
		BigInteger newGenInv = newGen.modPow(kparam.q.subtract(BigInteger.ONE), kparam.p);
		System.out.println("\nnewGen^-1: " + newGenInv);
		
		start = System.currentTimeMillis();
		ve = kp.publicKey.encryptVerifiableQOrderMessage(newGenInv);
		end = System.currentTimeMillis();
		System.out.println("newGen-1 Verifiable Encryption (" + (end-start) + "ms)\n" + ve);
		System.out.println("Auto verify : " + kp.publicKey.verifyQOrderMessageEncryption(newGenInv, ve));
		start = System.currentTimeMillis();
		dm = kp.privateKey.decryptQOrderMessage(ve.MESSAGE_ENCRYPTION);
		end = System.currentTimeMillis();
		System.out.println("newGen-1 decryption (" + (end-start) + "ms): " + dm.toString(radix));
			
	}
	
	
	/* **************************************************************************
	 * Parameters test
	 */
	public static void parametersTest(int modulusSize, int keySize, boolean testGenerator, boolean printElements) throws GeneralSecurityException{
		//test parameters program
		System.out.println("Create system parameters for a " + keySize + " bits key whith modulus of " + modulusSize + " bits.");
		ElGamalKeyParameters keyParam= new ElGamalKeyParameters(modulusSize, keySize, null, null);
		if (testGenerator)
			testParameters(keyParam, printElements);
	
		BigInteger newGen = keyParam.getQOrderGenerator(3);
		ElGamalKeyParameters newKeyParam = new ElGamalKeyParameters(keyParam.p, keyParam.q, keyParam.g);
		if (testGenerator)
			testParameters(newKeyParam, printElements);
		
		newKeyParam = new ElGamalKeyParameters(keyParam.p, keyParam.q, newGen);
		if (testGenerator)
			testParameters(newKeyParam, printElements);
		
	}
	
	public static void testParameters (ElGamalKeyParameters keyParam, boolean printElements)
	{
		System.out.println("p ("+ keyParam.p.bitLength()+") = " + keyParam.p);
		System.out.println("q ("+ keyParam.q.bitLength()+") = " + keyParam.q);
		System.out.println("g ("+ keyParam.g.bitLength()+") = " + keyParam.g);
		System.out.println("Test generator order...");
	
		BigInteger exponent = BigInteger.ZERO;
		BigInteger r;
		do {
			exponent = exponent.add(BigInteger.ONE);
			r = keyParam.g.modPow(exponent, keyParam.p);
			if(printElements)
				System.out.println("" + exponent + " - " + r);
		} while(r.compareTo(BigInteger.ONE) != 0);
		
		if(exponent.compareTo(keyParam.q)==0)
			System.out.println("Parameters VALIDATED!");
		else
			System.out.println("INVALID parameters!");
		
	}
}
