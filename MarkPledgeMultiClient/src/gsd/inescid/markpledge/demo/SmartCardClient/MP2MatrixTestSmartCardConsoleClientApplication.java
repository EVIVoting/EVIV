package gsd.inescid.markpledge.demo.SmartCardClient;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import gsd.inescid.crypto.ElGamalPrivateKey;
import gsd.inescid.crypto.ElGamalPublicKey;
import gsd.inescid.markpledge.MPKeyAndParameters;
import gsd.inescid.markpledge.MPUtil;
import gsd.inescid.markpledge.MarkPledgeType;
import gsd.inescid.markpledge.interfaces.IMPEncryptedVote;
import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.interfaces.IMPReceipt;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;
import gsd.inescid.markpledge.interfaces.IMPVoteAndReceipt;
import gsd.inescid.markpledge.smartclient.CardConstants;
import gsd.inescid.markpledge.smartclient.CardUtil;
import gsd.inescid.markpledge.smartclient.connection.CardException;
import gsd.inescid.markpledge.smartclient.connection.IMPCardConnection;
import gsd.inescid.markpledge.smartclient.connection.ISmartCardInterface;
import gsd.inescid.markpledge.smartclient.connection.JCOPCardInterface;
import gsd.inescid.markpledge.smartclient.connection.MultosCOMCardInterface;
import gsd.inescid.markpledge.smartclient.connection.PCSimulatedCardConnection;
import gsd.inescid.math.algebra.matrix.Matrix;
import gsd.inescid.math.algebra.matrix.MatrixUtil;

public class MP2MatrixTestSmartCardConsoleClientApplication {

	static final byte NUMBER_OF_CANDIDATES = 5;
	static final boolean WITH_PERFORMANCE_TIMES = true;
	static boolean WITH_PROOF = true;
	static MarkPledgeType BALLOT_TYPE = MarkPledgeType.MP3;
	static final int P_LENGTH = 1024;
	static final int Q_LENGTH = 512;
	static final int ALPHA = 24;
	static final boolean USE_SIMULATOR = true;
	static final String CARD_READER = "OMNIKEY CardMan 3x21 0";
	static final byte[] AID = new byte[]{(byte)0xF0, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x02, (byte)0x04};
	static MessageDigest MD;
	static final boolean SAME_GENERATOR = false;
	static final boolean USE_PC_SIMULATION = false;
	
	public static void main(String[] args) throws CardException, NoSuchAlgorithmException {
		
		MD = MessageDigest.getInstance("SHA-1");
		
		MPKeyAndParameters keyAndParam;
		keyAndParam = MPUtil.generateKeyAndParameters(P_LENGTH, Q_LENGTH, ALPHA, BALLOT_TYPE, SAME_GENERATOR);
		//keyAndParam = MPUtil.generateStaticKeyAndParameters(P_LENGTH, Q_LENGTH, ALPHA, BALLOT_TYPE, SAME_GENERATOR);
		
		IMPParameters param = keyAndParam.MP_PARAMETERS;
		param.setVoteCodeByteLength(CardConstants.CANDIDATE_CODE_LENGTH);
		
		ElGamalPublicKey kpub = keyAndParam.KEY_PAIR.publicKey;
		
		IMPCardConnection card;
		ISmartCardInterface cardInterface;
		
		/** create/init card connection **/
		if(!USE_PC_SIMULATION)
		{
			// create card connection
			//cardInterface = new MultosCOMCardInterface(USE_SIMULATOR);
			cardInterface = new JCOPCardInterface(USE_SIMULATOR);
			// init card connection
			cardInterface.init(CARD_READER,AID);
			card = CardUtil.getCardConnection(param,
					BALLOT_TYPE, cardInterface, WITH_PERFORMANCE_TIMES);
		}
		else
		{
			card = new PCSimulatedCardConnection(BALLOT_TYPE, param);
		}
		
		/*** BEGIN ***/
		
		/** STEP 1 - set parameters and create vote encryption **/
		IMPEncryptedVote encVote = card.setParametersAndCreateVoteEncryption(keyAndParam.MP_PARAMETERS, NUMBER_OF_CANDIDATES);
		
		
		/** STEP 2 - get pledge **/
		BigInteger pledge = card.getPledge();
		
				
		Matrix a = new Matrix();
		byte[] aux = CardUtil.bigIntegerToByteArray(kpub.p,	128);
		aux[0] = 3;
		aux[64] = 3;
		byte[] v = new byte[64];
		System.arraycopy(aux,0, v, 0, 64);
		a.a = new BigInteger(1,v);
		a.d = a.a;
		System.arraycopy(aux,64, v, 0, 64);
		a.b = new BigInteger(1,v);
		a.c = kpub.q.subtract(a.b);
		
		aux = CardUtil.bigIntegerToByteArray(kpub.g,128);
		System.arraycopy(aux,0, v, 0, 64);
		
		/*
		for(int i=0; i<44; i++)
			v[i] = 0;
		*/
		//v[63] = 2;
		BigInteger e = new BigInteger(1,v);
		
		//e = new BigInteger("8537377");
		
		Matrix mr = MatrixUtil.matrixModExpSO2Q(a, e, kpub.q); 
		System.out.println("Exponent: " + e);
		System.out.println("Matrix: \n" + a);

		System.out.println("\nExpected Result:\n   " + pledge.toString(16));

		System.out.println("Result: \n" + mr);
		
		
		
		/*** END ***/
		if(!USE_PC_SIMULATION)
			cardInterface.close();
		System.exit(0);
	}
}
