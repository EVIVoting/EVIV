package gsd.inescid.markpledge.interfaces;

import gsd.inescid.crypto.ElGamalPublicKey;

import java.math.BigInteger;

public interface IMPParameters {
	
	public ElGamalPublicKey getPublicKey();
	
	public BigInteger getP();
	public BigInteger getG();
	public BigInteger getH();
	public BigInteger getQ();
	
	public int getPLengthInBytes();
	public int getQLengthInBytes();
	
	public BigInteger getMP_G(); // can be the key generator
	public BigInteger getMP_GInv();
		
	public int getAlpha(); //number of bits of the verification code
	public int getAlphaByteLength();
	
	public int getVoteCodeByteLength();
	
	public void setPublicKey(ElGamalPublicKey key);
	public void setMPExponentialMessageGenerator(BigInteger mpG);
	public void setAlpha(int alpha);
	public void setVoteCodeByteLength(int length);
	
}
