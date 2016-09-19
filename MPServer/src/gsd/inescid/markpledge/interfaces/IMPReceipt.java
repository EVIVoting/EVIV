package gsd.inescid.markpledge.interfaces;

import java.math.BigInteger;

public interface IMPReceipt {
	public BigInteger[][] getReceiptValidity();
	public BigInteger[] getVerificationCodes();
	public BigInteger getChallenge();
	public byte[] getVoteHashCode();
	public byte[] getHash();
	public byte[] getSignature();
	public int getRotation();
	public String toString(String[]candidates);
}
