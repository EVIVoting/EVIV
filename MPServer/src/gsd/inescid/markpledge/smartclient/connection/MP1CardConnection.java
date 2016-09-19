package gsd.inescid.markpledge.smartclient.connection;

import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.markpledge.MarkPledgeType;
import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.smartclient.CardConstants;
import gsd.inescid.markpledge.smartclient.apdu.GetAPDU;
import gsd.inescid.markpledge.smartclient.apdu.SetAPDU;

import java.math.BigInteger;

public class MP1CardConnection extends MPAbstractCardConnection {

	protected int alpha;
	
	public MP1CardConnection(int pLength, int qLength, int voteCodeLength,
			boolean showPerformanceTimes, ISmartCardInterface cardConnection, int alpha)
	{
		super(pLength, qLength, voteCodeLength, CardConstants.ALPHA_MAX_VALUE/8, showPerformanceTimes, cardConnection);
		this.MP_TYPE = MarkPledgeType.MP1;
		this.alpha = alpha;
	}

	public void setParameters(IMPParameters param) throws CardException{
		super.setParameters(param);
		SetAPDU.SET_ALPHA.setP1(param.getAlpha());
		sendReceiveAPDU(SetAPDU.SET_ALPHA.getAPDUBytes(null));
	}
	
	
	public BigInteger[] getVerificationCodeValidityFactors(int candidateIndex) throws CardException 
	{
		BigInteger[] verificationFactors = new BigInteger[this.alpha];
		byte[] apdu;
		GetAPDU.GET_VCODE_VALIDITY_FACTOR.setExpectedResponceLength(Q_LENGTH);
		GetAPDU.GET_VCODE_VALIDITY_FACTOR.setP1(candidateIndex);
		for(int i=0; i<this.alpha; i++)
		{
			GetAPDU.GET_VCODE_VALIDITY_FACTOR.setP2(i);
			apdu = GetAPDU.GET_VCODE_VALIDITY_FACTOR.getAPDUBytes();
			verificationFactors[i] = new BigInteger(1, sendReceiveAPDU(apdu));
		}	
		return verificationFactors;
	}

	
	public ElGamalEncryption[] getCandidateEncryption(int candidateIndex) throws CardException 
	{
		ElGamalEncryption[] candidateEncryption = new ElGamalEncryption[2*this.alpha];
		GetAPDU.GET_CANDIDATE_ENCRYPTION_X.setExpectedResponceLength(P_LENGTH);
		GetAPDU.GET_CANDIDATE_ENCRYPTION_Y.setExpectedResponceLength(P_LENGTH);
		GetAPDU.GET_CANDIDATE_ENCRYPTION_X.setP1(candidateIndex);
		GetAPDU.GET_CANDIDATE_ENCRYPTION_Y.setP1(candidateIndex);
		
		// get the BMP encryptions)
		getCandidateEncryption(candidateEncryption); 
		return candidateEncryption;
	}
	
	protected void getCandidateEncryption(ElGamalEncryption[] candidateEncryption) throws CardException
	{
		byte[] encX, encY;
		for(int i=0; i<candidateEncryption.length; i++)
		{
			GetAPDU.GET_CANDIDATE_ENCRYPTION_X.setP1(i);
			GetAPDU.GET_CANDIDATE_ENCRYPTION_Y.setP1(i);
			encX = sendReceiveAPDU(GetAPDU.GET_CANDIDATE_ENCRYPTION_X.getAPDUBytes());
			encY = sendReceiveAPDU(GetAPDU.GET_CANDIDATE_ENCRYPTION_Y.getAPDUBytes());
			candidateEncryption[i] = new ElGamalEncryption(encX, encY);
		}
	}
	
	

}
