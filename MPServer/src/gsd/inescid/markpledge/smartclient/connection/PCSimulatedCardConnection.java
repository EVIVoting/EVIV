package gsd.inescid.markpledge.smartclient.connection;

import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.markpledge.CGS97BallotValidity;
import gsd.inescid.markpledge.MPVoteReceiptFactory;
import gsd.inescid.markpledge.MarkPledgeType;
import gsd.inescid.markpledge.interfaces.IMPEncryptedVote;
import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.interfaces.IMPReceipt;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;
import gsd.inescid.markpledge.interfaces.IMPVoteReceiptFactory;

import java.math.BigInteger;
import java.security.SecureRandom;

public class PCSimulatedCardConnection implements IMPCardConnection {

	protected IMPVoteReceiptFactory voteFactory;
	protected IMPEncryptedVote vote;
	protected IMPReceipt receipt;
	protected IMPValidityProof validity;
	protected int currentCandidate;
	protected int selectedCandidate;
	
	public PCSimulatedCardConnection(MarkPledgeType type, IMPParameters param)
	{
		this.voteFactory = MPVoteReceiptFactory.getInstance(
				type, param, new SecureRandom());
	}
	
	public void createCGS97Proof(int candidateIndex) throws CardException {
		if (candidateIndex == 0) //create new vote validity
			this.validity = this.voteFactory.getValidityProof();
	}

	public void createCandidateEncryption(int candidateIndex)
			throws CardException {
	
		this.currentCandidate = candidateIndex;
		if (candidateIndex == 0) //create new vote encryption
			this.vote = this.voteFactory.getEncryptedVote();	
	}

	public CGS97BallotValidity getCGS97Proof() throws CardException {
		return this.validity.getCanonicalVoteCGS97Proof()[this.currentCandidate];
	}

	public ElGamalEncryption[] getCandidateEncryption(int candidateIndex)
			throws CardException {
		return this.vote.getCandidateEncryption(candidateIndex);
	}

	public BigInteger getPledge() throws CardException {
		return this.voteFactory.getPledge();
	}

	public BigInteger getSumProof() throws CardException {
		return this.validity.getVoteSumProof();
	}

	public BigInteger getVerificationCode(int candidateIndex)
			throws CardException {
		return this.receipt.getVerificationCodes()[candidateIndex];
	}

	public BigInteger[] getVerificationCodeValidityFactors(int candidateIndex)
			throws CardException {
		return this.receipt.getReceiptValidity()[candidateIndex];
	}

	//IGNORED METHOD
	public byte[] getVoteEncryptionSignature() throws CardException {
		// TODO Auto-generated method stub
		return null;
	}

	//IGNORED METHOD
	public byte[] getVoteHash(int hashLength) throws CardException {
		// TODO Auto-generated method stub
		return null;
	}

	//IGNORED METHOD
	public byte[] getVoteReceiptHash(int hashLength) throws CardException {
		// TODO Auto-generated method stub
		return null;
	}

	//IGNORED METHOD
	public byte[] getVoteReceiptSignature() throws CardException {
		// TODO Auto-generated method stub
		return null;
	}

	public void prepareBallot(int numberOfCandidates, MarkPledgeType type)
			throws CardException {
		this.voteFactory.init(numberOfCandidates);	
	}

	
	public void prepareReceipt(BigInteger chal) throws CardException {
		this.receipt = this.voteFactory.getReceipt(this.selectedCandidate, chal);
	}

	public int selectCandidate(BigInteger candidateVoteCode)
			throws CardException {
		//the vote code is not translated
		this.selectedCandidate = candidateVoteCode.intValue();
		//the rotation is not known yet :(
		return 0;
	}

	//IGNORED METHOD
	public byte[] sendReceiveAPDU(byte[] command) throws CardException {
		// TODO Auto-generated method stub
		return null;
	}

	//IGNORED METHOD
	public void setParameters(IMPParameters param) throws CardException {
		// TODO Auto-generated method stub
	}

	/********************/
	/*** Bulk methods ***/
	/********************/
	
	public IMPEncryptedVote setParametersAndCreateVoteEncryption(
			IMPParameters param, int numberOfCandidates) throws CardException {
		this.voteFactory.init(numberOfCandidates);	
		this.vote = this.voteFactory.getEncryptedVote();
		return this.vote;
	}

	public IMPValidityProof getValidity(int numberOfCandidates)
			throws CardException {
		this.validity = this.voteFactory.getValidityProof();
		return this.validity;
	}

	public IMPReceipt getVoteReceipt(BigInteger candidateVoteCode,
			BigInteger chal, int numberOfCandidates) throws CardException {
		//the vote code is not translated
		this.receipt = this.voteFactory.getReceipt(candidateVoteCode.intValue(), chal);
		return this.receipt;
	
	}
}
