package gsd.inescid.markpledge.demo.SmartCardClient;

import gsd.inescid.crypto.ElGamalPrivateKey;
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
import gsd.inescid.markpledge.smartclient.connection.MultosCOMCardInterface;
import gsd.inescid.markpledge.smartclient.connection.PCSimulatedCardConnection;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SmartCardConsoleClientApplication {

	static final byte NUMBER_OF_CANDIDATES = 4;
	static final boolean WITH_PERFORMANCE_TIMES = true;
	static boolean WITH_PROOF = true;
	static MarkPledgeType BALLOT_TYPE = MarkPledgeType.MP2;
	static final int P_LENGTH = 1024;
	static final int Q_LENGTH = 160;
	static final int ALPHA = 24;
	static final boolean USE_SIMULATOR = false;
	static final String CARD_READER = "OMNIKEY CardMan 3x21 0";
	//static final byte[] AID = new byte[]{(byte)0xF0, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x02, (byte)0x04};
	static final byte[] AID = new byte[]{(byte)0xF0, (byte)0x00, (byte)0x00, (byte)0x02};
	
	static MessageDigest MD;
	static final boolean SAME_GENERATOR = false;
	static final boolean USE_PC_SIMULATION = false;
	
	public static void main(String[] args) throws CardException, NoSuchAlgorithmException {
		
		MD = MessageDigest.getInstance("SHA-1");
		
		MPKeyAndParameters keyAndParam;
		//keyAndParam = MPUtil.generateKeyAndParameters(P_LENGTH, Q_LENGTH, ALPHA, BALLOT_TYPE, SAME_GENERATOR);
		keyAndParam = MPUtil.generateStaticKeyAndParameters(P_LENGTH, Q_LENGTH, ALPHA, BALLOT_TYPE, SAME_GENERATOR);
		
		IMPParameters param = keyAndParam.MP_PARAMETERS;
		param.setVoteCodeByteLength(CardConstants.CANDIDATE_CODE_LENGTH);
		
		//ElGamalPublicKey kpub = keyAndParam.KEY_PAIR.publicKey;
		ElGamalPrivateKey kpri = keyAndParam.KEY_PAIR.privateKey;
		
		IMPCardConnection card;
		ISmartCardInterface cardInterface;
		
		/** create/init card connection **/
		if(!USE_PC_SIMULATION)
		{
			// create card connection
			cardInterface = new MultosCOMCardInterface(USE_SIMULATOR);
			//cardInterface = new JCOPCardInterface(USE_SIMULATOR);
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
		System.out.println("\nPledge: " + pledge.toString(16));

		
		/** STEP 3 - create and get receipt **/
		//create challenge
		BigInteger chal = MPUtil.createChallenge(param, BALLOT_TYPE);
		//select candidate
		BigInteger voteCode = BigInteger.ONE;
		//get receipt
		IMPReceipt receipt = card.getVoteReceipt(voteCode, chal, NUMBER_OF_CANDIDATES);
		System.out.println(MPUtil.getVoteReceiptText(receipt));
		
		/** STEP 4 - get canonical vote verification factors **/
		IMPValidityProof validity = null;
		if (WITH_PROOF && BALLOT_TYPE != MarkPledgeType.MP1)
			validity = card.getValidity(NUMBER_OF_CANDIDATES);
		
		/** STEP 5 - verify vote **/
		//update the called method as soon as new MPVoteAndReceipt classes are created
		IMPVoteAndReceipt voteAndReceipt = MPUtil.getVoteAndReceipt(BALLOT_TYPE, encVote, receipt, validity);
		
		
		System.out.println("Recibo OK: " + voteAndReceipt.verifyReceipt(param, MD));
		if(WITH_PROOF && BALLOT_TYPE != MarkPledgeType.MP1)
		{
			System.out.println("Canonical vote OK: " + voteAndReceipt.verifyCanonicalVote(param, MD));
			System.out.println("Vote sum check OK: " + voteAndReceipt.verifyVoteSum(param, 1));
		}
		
		/** SETP 6 decrypt vote */
		//update to a call to getCanonicalVoteElementsAsArray for MP1
		System.out.println(MPUtil.decryptedVote(voteAndReceipt.getCanonicalVote(param), kpri, param, BALLOT_TYPE));
			
		/*** END ***/
		if(!USE_PC_SIMULATION)
			cardInterface.close();
		System.exit(0);
	}
}
