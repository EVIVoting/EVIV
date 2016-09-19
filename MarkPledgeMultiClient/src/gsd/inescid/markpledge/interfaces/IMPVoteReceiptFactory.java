package gsd.inescid.markpledge.interfaces;

import java.math.BigInteger;

public interface IMPVoteReceiptFactory {

	public void init(int numberOfCandidates);
	public IMPEncryptedVote getEncryptedVote();
	public BigInteger getPledge();
	public IMPReceipt getReceipt(int selectedCandidateIndex, BigInteger challenge);
	public IMPValidityProof getValidityProof();
	public IMPVoteAndReceipt getNewVoteAndReceipt(boolean withValidity, int numberOfCandidates);
}
