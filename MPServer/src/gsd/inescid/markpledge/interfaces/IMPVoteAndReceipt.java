package gsd.inescid.markpledge.interfaces;

import gsd.inescid.crypto.ElGamalEncryption;

import java.security.MessageDigest;

public interface IMPVoteAndReceipt 
{
	public IMPEncryptedVote getVoteEncryption();
	public IMPReceipt getVoteReceipt();
	public IMPValidityProof getVoteValidityProof();
	public ElGamalEncryption[] getCanonicalVote(IMPParameters param);
	public ElGamalEncryption[][] getCanonicalVoteElementsAsArray(IMPParameters param);
	public boolean verifyReceipt(IMPParameters param, MessageDigest md);
	public boolean verifyCanonicalVote(IMPParameters param, MessageDigest md);
	public boolean verifyVoteSum(IMPParameters param, int numberOfSelectedCandidates);
	public boolean verifyAll(IMPParameters param, int nSelectedCandidates, MessageDigest md);
}
