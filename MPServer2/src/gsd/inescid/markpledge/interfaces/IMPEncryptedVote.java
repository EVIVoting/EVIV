package gsd.inescid.markpledge.interfaces;

import gsd.inescid.crypto.ElGamalEncryption;

public interface IMPEncryptedVote {
	public ElGamalEncryption[][] getEncryptedVote();
	public ElGamalEncryption[] getCandidateEncryption(int candidateEncryptionIndex);
	public byte[] getHash();
	public boolean isChainHash();
	public byte[] getSignature();
}
