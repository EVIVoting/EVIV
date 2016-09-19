package gsd.inescid.markpledge.smartclient.connection;

import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.markpledge.MarkPledgeType;
import gsd.inescid.markpledge.smartclient.apdu.GetAPDU;

import java.math.BigInteger;

public class MP1ACardConnection extends MP1CardConnection {

	public MP1ACardConnection(int pLength, int qLength, int voteCodeLength, 
			boolean showPerformanceTimes, ISmartCardInterface cardConnection, int alpha) 
	{
		super(pLength, qLength, voteCodeLength, showPerformanceTimes, cardConnection,
				alpha);
		this.MP_TYPE = MarkPledgeType.MP1A;
	}
	
	public BigInteger[] getVerificationCodeValidityFactors(int candidateIndex) throws CardException 
	{
		BigInteger[] validityFactors = new BigInteger[2*this.alpha];
		byte[] apdu;
		GetAPDU.GET_MP1A_BMP_CONFORMITY_FACTOR.setExpectedResponceLength(Q_LENGTH);
		GetAPDU.GET_MP1A_BMP_CONFORMITY_FACTOR.setP1(candidateIndex);
		for(int i=0; i<this.alpha; i++)
		{
			GetAPDU.GET_MP1A_BMP_CONFORMITY_FACTOR.setP2(i);
			apdu = GetAPDU.GET_MP1A_BMP_CONFORMITY_FACTOR.getAPDUBytes();
			validityFactors[i] = new BigInteger(1, sendReceiveAPDU(apdu));
		}	
		
		BigInteger[] verificationFactors = super.getVerificationCodeValidityFactors(candidateIndex);
		System.arraycopy(verificationFactors, 0, validityFactors, this.alpha, this.alpha);
		return validityFactors;
		
	}

	
	public ElGamalEncryption[] getCandidateEncryption(int candidateIndex) throws CardException 
	{
		ElGamalEncryption[] candidateEncryption = new ElGamalEncryption[2*this.alpha + 1];
		GetAPDU.GET_CANDIDATE_ENCRYPTION_X.setExpectedResponceLength(P_LENGTH);
		GetAPDU.GET_CANDIDATE_ENCRYPTION_Y.setExpectedResponceLength(P_LENGTH);
		GetAPDU.GET_CANDIDATE_ENCRYPTION_X.setP1(candidateIndex);
		GetAPDU.GET_CANDIDATE_ENCRYPTION_Y.setP1(candidateIndex);
		
		// get the ElGamal encryptions)
		super.getCandidateEncryption(candidateEncryption); 
		return candidateEncryption;
	}
}
