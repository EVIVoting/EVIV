package gsd.inescid.markpledge.smartclient.connection;

import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.markpledge.MPEncryptedVote;
import gsd.inescid.markpledge.MPReceipt;
import gsd.inescid.markpledge.MPValidityProof;
import gsd.inescid.markpledge.MarkPledgeType;
import gsd.inescid.markpledge.interfaces.IMPEncryptedVote;
import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.interfaces.IMPReceipt;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;
import gsd.inescid.markpledge.smartclient.CardUtil;
import gsd.inescid.markpledge.smartclient.apdu.ActionAPDU;
import gsd.inescid.markpledge.smartclient.apdu.GetAPDU;
import gsd.inescid.markpledge.smartclient.apdu.SetAPDU;
import gsd.inescid.markpledge3.CGS97BallotValidity;

import java.math.BigInteger;



/**
 * Abstract class that defines and implements the main smart card interface
 * 
 * @author Rui Joaquim
 *
 */
public abstract class MPAbstractCardConnection implements IMPCardConnection {

	protected final boolean PERFORMANCE_TIMES;
	protected final int P_LENGTH;
	protected final int Q_LENGTH;
	protected final int VOTE_CODE_LENGTH;
	protected final int VERIFICATION_CODE_AND_CHALLANGE_LENGTH;
	protected MarkPledgeType MP_TYPE;
	private final ISmartCardInterface CARD_CONNECTION;
	
	
	protected MPAbstractCardConnection(int pLength, int qLength, int voteCodeLength, int chalLength,  
			boolean showPerformanceTimes, ISmartCardInterface cardConnection)
	{
		this.PERFORMANCE_TIMES = showPerformanceTimes;
		this.P_LENGTH = pLength;
		this.Q_LENGTH = qLength;
		this.VOTE_CODE_LENGTH = voteCodeLength;
		this.CARD_CONNECTION = cardConnection;
		this.VERIFICATION_CODE_AND_CHALLANGE_LENGTH = chalLength;
	}
	
	/**
	 * Redirect the apdu command to the card connection.
	 * @param command command APDU
	 * @returns the data received in the response APDU without the status word.
	 * @throws CardException if the response APDU reports an error.
	 */
	public byte[] sendReceiveAPDU(byte[] command) throws CardException
	{
		return this.CARD_CONNECTION.sendReceiveAPDU(command);
	}
	
	
	/**
	 * Set MP parameters, number of candidates and the MarkPledge ballot type.
	 * @param param the MP parameters
	 * @param numberOfCandidates the number of candidates running in the election
	 */
	public IMPEncryptedVote setParametersAndCreateVoteEncryption(IMPParameters param, int numberOfCandidates)throws CardException
	{
		long start, end;
		//set parameters (load key material)
		start = System.currentTimeMillis();
		setParameters(param);
		end = System.currentTimeMillis();
		if(PERFORMANCE_TIMES)
			System.out.println("Load parameters: " + (end-start));

		// prepare ballot (generate random values)
		start = System.currentTimeMillis();
		prepareBallot(numberOfCandidates, this.MP_TYPE);
		end = System.currentTimeMillis();
		if(PERFORMANCE_TIMES)
			System.out.println("Prepare ballot: " + (end-start));
	
		// get vote encryption
		start = System.currentTimeMillis();
		MPEncryptedVote voteEnc = new MPEncryptedVote(numberOfCandidates);
		ElGamalEncryption[] candidateEnc;
		for(int i=0; i<numberOfCandidates; i++)
		{
			createCandidateEncryption(i);
			candidateEnc = getCandidateEncryption(i);
			voteEnc.setCandidateVote(i, candidateEnc);
		}
		voteEnc.setSignature(getVoteEncryptionSignature());
		end = System.currentTimeMillis();
		if(PERFORMANCE_TIMES)
			System.out.println("Create ballot: " + (end-start));
	
		return voteEnc;
	}

		
	/**
	 * Set challenge, get receipt and get vote rotation.
	 * @param voteCode the vote code of the selected candidate
	 * @param chal challenge value 
	 * @param numberOfCandidates number of candidates running in the election
	 */
	public IMPReceipt getVoteReceipt(BigInteger candidateVoteCode, BigInteger chal, int numberOfCandidates) throws CardException
	{
		long start, end;
		MPReceipt receipt = new MPReceipt(numberOfCandidates);
		receipt.setChallenge(chal);
		
		//prepare receipt
		start = System.currentTimeMillis();
		prepareReceipt(chal);
		end = System.currentTimeMillis();
		if(PERFORMANCE_TIMES)
			System.out.println("Prepare receipt(set chal): " + (end-start));
		
		//download receipt
		start = System.currentTimeMillis();
		for(int i=0; i < numberOfCandidates; i++)
		{
			receipt.setVerificationCode(getVerificationCode(i), i);
			receipt.setValidity(getVerificationCodeValidityFactors(i), i);
		}
		end = System.currentTimeMillis();
		if(PERFORMANCE_TIMES)
			System.out.println("Download receipt: " + (end-start));
		
		//select candidate
		start = System.currentTimeMillis();
		receipt.setRotation(selectCandidate(candidateVoteCode));
		receipt.setSignature(getVoteReceiptSignature());
		end = System.currentTimeMillis();
		if(PERFORMANCE_TIMES)
			System.out.println("Select candidate (get rotation and signature): " + (end-start));
		
		return receipt;
	}
	

	public IMPValidityProof getValidity(int numberOfCandidates) throws CardException
	{
		long start, end;
		MPValidityProof validity = new MPValidityProof(numberOfCandidates);
		//get canonical vote validity proofs
		start = System.currentTimeMillis();
		for(int i=0; i<numberOfCandidates; i++)
		{
			createCGS97Proof(i);
			validity.setCanonicalVoteProof(getCGS97Proof(), i);
		}
		validity.setVoteSumProof(getSumProof());
		end = System.currentTimeMillis();
		if(PERFORMANCE_TIMES)
			System.out.println("Canonical vote validity proofs: " + (end-start));
		return validity;
	}
	
		
	public void prepareBallot(int numberOfCandidates, MarkPledgeType type) throws CardException{
		byte[] apdu;
		ActionAPDU.PREPARE_BALLOT.setP1P2(numberOfCandidates, type.getTypeValue());
		apdu = ActionAPDU.PREPARE_BALLOT.getAPDUBytes(null);
		sendReceiveAPDU(apdu);
	}

	
	public void createCandidateEncryption(int candidateIndex) throws CardException{
		byte[] apdu;
		ActionAPDU.CREATE_CANDIDATE_ENCRYPTION.setP1(candidateIndex);
		apdu = ActionAPDU.CREATE_CANDIDATE_ENCRYPTION.getAPDUBytes(null);
		sendReceiveAPDU(apdu);
	}



	public void createCGS97Proof(int candidateIndex)throws CardException {
		byte[] apdu;
		ActionAPDU.CREATE_CGS97_CANDIDATE_PROOF.setP1(candidateIndex);
		apdu = ActionAPDU.CREATE_CGS97_CANDIDATE_PROOF.getAPDUBytes(null);
		sendReceiveAPDU(apdu);
	}


	public CGS97BallotValidity getCGS97Proof()throws CardException{
		BigInteger[] aux = new BigInteger[9];
		byte[] apdu;
		GetAPDU.GET_CGS97_A1.setExpectedResponceLength(P_LENGTH);
		apdu = GetAPDU.GET_CGS97_A1.getAPDUBytes();
		aux[0] = new BigInteger(1, sendReceiveAPDU(apdu));
		
		GetAPDU.GET_CGS97_A2.setExpectedResponceLength(P_LENGTH);
		apdu = GetAPDU.GET_CGS97_A2.getAPDUBytes();
		aux[1] = new BigInteger(1, sendReceiveAPDU(apdu));
		
		GetAPDU.GET_CGS97_B1.setExpectedResponceLength(P_LENGTH);
		apdu = GetAPDU.GET_CGS97_B1.getAPDUBytes();
		aux[2] = new BigInteger(1, sendReceiveAPDU(apdu));
		
		GetAPDU.GET_CGS97_B2.setExpectedResponceLength(P_LENGTH);
		apdu = GetAPDU.GET_CGS97_B2.getAPDUBytes();
		aux[3] = new BigInteger(1, sendReceiveAPDU(apdu));
		
		GetAPDU.GET_CGS97_R1.setExpectedResponceLength(Q_LENGTH);
		apdu = GetAPDU.GET_CGS97_R1.getAPDUBytes();
		aux[4] = new BigInteger(1, sendReceiveAPDU(apdu));
		
		GetAPDU.GET_CGS97_R2.setExpectedResponceLength(Q_LENGTH);
		apdu = GetAPDU.GET_CGS97_R2.getAPDUBytes();
		aux[5] = new BigInteger(1, sendReceiveAPDU(apdu));
		
		GetAPDU.GET_CGS97_D1.setExpectedResponceLength(Q_LENGTH);
		apdu = GetAPDU.GET_CGS97_D1.getAPDUBytes();
		aux[6] = new BigInteger(1, sendReceiveAPDU(apdu));
		
		GetAPDU.GET_CGS97_D2.setExpectedResponceLength(Q_LENGTH);
		apdu = GetAPDU.GET_CGS97_D2.getAPDUBytes();
		aux[7] = new BigInteger(1, sendReceiveAPDU(apdu));
		
		GetAPDU.GET_CGS97_C.setExpectedResponceLength(Q_LENGTH);
		apdu = GetAPDU.GET_CGS97_C.getAPDUBytes();
		aux[8] = new BigInteger(1, sendReceiveAPDU(apdu));
		
		return new CGS97BallotValidity(aux[0], aux[1], aux[2], aux[3], aux[4], aux[5], aux[6], aux[7], aux[8]);
	}


	public BigInteger getSumProof()throws CardException {
		byte[] apdu;
		GetAPDU.GET_SUM_VALIDITY_FACTOR.setExpectedResponceLength(Q_LENGTH);
		apdu = GetAPDU.GET_SUM_VALIDITY_FACTOR.getAPDUBytes();
		return new BigInteger(1, sendReceiveAPDU(apdu));
	}

	public BigInteger getPledge() throws CardException{
		byte[] apdu;
		GetAPDU.GET_PLEDGE.setExpectedResponceLength(VERIFICATION_CODE_AND_CHALLANGE_LENGTH);
		apdu = GetAPDU.GET_PLEDGE.getAPDUBytes();
		return new BigInteger(1, sendReceiveAPDU(apdu));
	}

	
	public void prepareReceipt(BigInteger chal)throws CardException {
		byte[] apdu;
		apdu = ActionAPDU.PREPARE_RECEIPT.getAPDUBytes(
				CardUtil.bigIntegerToByteArray(chal, VERIFICATION_CODE_AND_CHALLANGE_LENGTH));
		sendReceiveAPDU(apdu);
	}

	
	public BigInteger getVerificationCode(int candidateIndex) throws CardException{
		byte[] apdu;
		GetAPDU.GET_VCODE.setExpectedResponceLength(VERIFICATION_CODE_AND_CHALLANGE_LENGTH);
		GetAPDU.GET_VCODE.setP1(candidateIndex);
		apdu = GetAPDU.GET_VCODE.getAPDUBytes();
		return new BigInteger(1, sendReceiveAPDU(apdu));
	}

	
	public int selectCandidate(BigInteger voteCode) throws CardException{
		byte[] apdu;
		apdu = ActionAPDU.SELECT_CANDIDATE.getAPDUBytes(
				CardUtil.bigIntegerToByteArray(voteCode,VOTE_CODE_LENGTH));
		return sendReceiveAPDU(apdu)[0];
	}
	
	public byte[] getVoteEncryptionSignature() throws CardException {
		byte[] apdu;
		GetAPDU.GET_VOTE_ENCRYPTION_SIGNATURE.setExpectedResponceLength(P_LENGTH);
		apdu = GetAPDU.GET_VOTE_ENCRYPTION_SIGNATURE.getAPDUBytes();
		return sendReceiveAPDU(apdu);
	}

	public byte[] getVoteReceiptSignature() throws CardException {
		byte[] apdu;
		GetAPDU.GET_VOTE_AND_RECEIPT_SIGNATURE.setExpectedResponceLength(P_LENGTH);
		apdu = GetAPDU.GET_VOTE_AND_RECEIPT_SIGNATURE.getAPDUBytes();
		return sendReceiveAPDU(apdu);
	}

	//need to be augmented in MP1 and MP2
	public void setParameters(IMPParameters param) throws CardException{
		byte[] apdu;
		apdu = SetAPDU.SET_P.getAPDUBytes(CardUtil.bigIntegerToByteArray(param.getP(), P_LENGTH));
		sendReceiveAPDU(apdu);
		apdu = SetAPDU.SET_G.getAPDUBytes(CardUtil.bigIntegerToByteArray(param.getG(), P_LENGTH));
		sendReceiveAPDU(apdu);
		apdu = SetAPDU.SET_H.getAPDUBytes(CardUtil.bigIntegerToByteArray(param.getH(), P_LENGTH));
		sendReceiveAPDU(apdu);
		apdu = SetAPDU.SET_Q.getAPDUBytes(CardUtil.bigIntegerToByteArray(param.getQ(), Q_LENGTH));
		sendReceiveAPDU(apdu);
		apdu = SetAPDU.SET_MP_G.getAPDUBytes(CardUtil.bigIntegerToByteArray(param.getMP_G(), P_LENGTH));
		sendReceiveAPDU(apdu);
		apdu = SetAPDU.SET_MP_GINV.getAPDUBytes(CardUtil.bigIntegerToByteArray(param.getMP_GInv(), P_LENGTH));
		sendReceiveAPDU(apdu);
	}

	//To define in the particular implementations
	public abstract BigInteger[] getVerificationCodeValidityFactors(int candidateIndex) throws CardException;
	public abstract ElGamalEncryption[] getCandidateEncryption(int candidateIndex) throws CardException;

	
	
	//FOR TESTS ONLY
	public byte[] getVoteHash(int hashLength) throws CardException {
		byte[] apdu;
		GetAPDU.GET_VOTE_HASH.setExpectedResponceLength(hashLength);
		apdu = GetAPDU.GET_VOTE_HASH.getAPDUBytes();
		return sendReceiveAPDU(apdu);
	}

	public byte[] getVoteReceiptHash(int hashLength) throws CardException {
		byte[] apdu;
		GetAPDU.GET_VOTE_AND_RECEIPT_HASH.setExpectedResponceLength(hashLength);
		apdu = GetAPDU.GET_VOTE_AND_RECEIPT_HASH.getAPDUBytes();
		return sendReceiveAPDU(apdu);
	}

}























