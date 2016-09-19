package gsd.inescid.markpledge;

import gsd.inescid.crypto.ElGamalPublicKey;
import gsd.inescid.crypto.util.CryptoUtil;
import gsd.inescid.markpledge.interfaces.IMPParameters;

import java.math.BigInteger;

public class MPParameters implements IMPParameters {

	private ElGamalPublicKey kpub;
	private int pLength;
	private int qLength;
	private BigInteger mpG;
	private BigInteger mpGInv;
	private int alpha;
	private int alphaLength;
	private int voteCodeLength;
	
	public MPParameters(){}
	
	public MPParameters(ElGamalPublicKey key, BigInteger mpG, int alpha, int voteCodeLength)
	{
		setPublicKey(key);
		setMPExponentialMessageGenerator(mpG);
		setAlpha(alpha);
		setVoteCodeByteLength(voteCodeLength);
	}
	
	public ElGamalPublicKey getPublicKey() {
		return this.kpub;
	}

	public BigInteger getP() {
		return this.kpub.p;
	}

	public BigInteger getG() {
		return this.kpub.g;
	}

	public BigInteger getH() {
		return this.kpub.h;
	}

	public BigInteger getQ() {
		return this.kpub.q;
	}

	public int getPLengthInBytes() {
		return this.pLength;
	}

	public int getQLengthInBytes() {
		return this.qLength;
	}

	public BigInteger getMP_G() {
		return this.mpG;
	}

	public BigInteger getMP_GInv() {
		return this.mpGInv;
	}

	public int getAlpha() {
		return this.alpha;
	}
	
	public int getAlphaByteLength() {
		return this.alphaLength;
	}

	
	public int getVoteCodeByteLength() {
		return this.voteCodeLength;
	}

	public void setPublicKey(ElGamalPublicKey key) {
		this.kpub = key;
		this.pLength = CryptoUtil.getLengthInBytes(this.kpub.p.bitLength());
		this.qLength = CryptoUtil.getLengthInBytes(this.kpub.q.bitLength());
	}

	public void setMPExponentialMessageGenerator(BigInteger mpG) {
		this.mpG = mpG;
		this.mpGInv = this.mpG.modPow(getQ().subtract(BigInteger.ONE),getP());
	}

	public void setAlpha(int alpha) {
		this.alpha = alpha;
		this.alphaLength = CryptoUtil.getLengthInBytes(this.alpha);
	}


	public void setVoteCodeByteLength(int length) {
		this.voteCodeLength = length;
	}

}
