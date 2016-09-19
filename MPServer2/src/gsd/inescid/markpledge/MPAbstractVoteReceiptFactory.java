package gsd.inescid.markpledge;

import gsd.inescid.markpledge.interfaces.IMPEncryptedVote;
import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.interfaces.IMPReceipt;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;
import gsd.inescid.markpledge.interfaces.IMPVoteAndReceipt;
import gsd.inescid.markpledge.interfaces.IMPVoteReceiptFactory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public abstract class MPAbstractVoteReceiptFactory implements IMPVoteReceiptFactory{
	
	protected MarkPledgeType type;
	protected IMPParameters param;
	protected int numberOfCandidates;
	protected int yesVotePosition;
	 
	
	protected MPEncryptedVote voteEnc;
	protected MPReceipt receipt;
	protected MPValidityProof validity;
	
	protected Random randomSource;
	protected MessageDigest md;
	
	protected MPAbstractVoteReceiptFactory(MarkPledgeType type, IMPParameters param)
	{
		this.type = type;
		this.param = param;
		this.randomSource = new SecureRandom();
		try {
			this.md = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		};
	}
	
	public void init(int numberOfCandidates)
	{
		this.numberOfCandidates = numberOfCandidates;
		this.yesVotePosition = this.randomSource.nextInt(this.numberOfCandidates);
		//System.out.println("YESVote: " + this.yesVotePosition);
	}
	
	public IMPVoteAndReceipt getNewVoteAndReceipt(boolean withValidity, int numberOfCandidates)
	{
		init(numberOfCandidates);
		IMPEncryptedVote vote = getEncryptedVote();
		BigInteger chal = MPUtil.createChallenge(this.param, this.type);
		IMPReceipt receipt = getReceipt(this.randomSource.nextInt(this.numberOfCandidates),
				chal);
		IMPValidityProof validity = null;
		if(withValidity)
			validity = getValidityProof();
		return MPUtil.getVoteAndReceipt(this.type, vote, receipt, validity);
	}
	
	protected int getVoteRotation(int selection)
	{
		//rotation calculus
		int rotation = selection - this.yesVotePosition;
		if (rotation < 0)
			rotation += this.numberOfCandidates;
		return rotation;
	}
	
	protected void setReceiptHash()
	{
		//TODO
	}
	
	protected void setVoteHash()
	{
		//TODO
	}
}
