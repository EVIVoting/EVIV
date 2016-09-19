package gsd.inescid.markpledge.smartclient.connection;


import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.markpledge.MarkPledgeType;
import gsd.inescid.markpledge.interfaces.IMPEncryptedVote;
import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.interfaces.IMPReceipt;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;
import gsd.inescid.markpledge3.CGS97BallotValidity;

import java.math.BigInteger;



/**
 * MarkPledge generic smart card interface
 * 
 * @author Rui Joaquim
 *
 */
public interface IMPCardConnection {
	
	/*** Bulk methods ***************/
	public IMPEncryptedVote setParametersAndCreateVoteEncryption(IMPParameters param, int numberOfCandidates) throws CardException;	
	public IMPReceipt getVoteReceipt(BigInteger candidateVoteCode, BigInteger chal, int numberOfCandidates) throws CardException;
	public IMPValidityProof getValidity(int numberOfCandidates) throws CardException;
	
	/*******************************************************
	/*--- Step by step methods ----------------------------*
	 ******************************************************/ 
	public void setParameters(IMPParameters param)throws CardException;
	public void prepareBallot(int numberOfCandidates, MarkPledgeType type)throws CardException;
	public void createCandidateEncryption(int candidateIndex)throws CardException;
	public void createCGS97Proof(int candidateIndex)throws CardException;
	
	public int selectCandidate(BigInteger candidateVoteCode)throws CardException;
	public void prepareReceipt(BigInteger chal)throws CardException;
	
	public CGS97BallotValidity getCGS97Proof()throws CardException;
	public BigInteger getSumProof()throws CardException;
	
	public BigInteger getPledge()throws CardException;
	public BigInteger getVerificationCode(int candidateIndex)throws CardException;
	
	public byte[] getVoteEncryptionSignature() throws CardException;
	public byte[] getVoteReceiptSignature() throws CardException;
	
	//the next two methods have a different implementations as in MP1 we have 2.alpha + 1 encryptions
	//and in MP2 and MP3 we only have 2 encryptions
	public BigInteger[] getVerificationCodeValidityFactors(int candidateIndex)throws CardException;
	public ElGamalEncryption[] getCandidateEncryption(int candidateIndex)throws CardException;
	
	
	//to send the individual APDUs to the card
	public byte[] sendReceiveAPDU(byte[] command) throws CardException;
	
	/** only for test purposes */
	public byte[] getVoteHash(int hashLength) throws CardException;
	public byte[] getVoteReceiptHash(int hashLength) throws CardException;
	
}
