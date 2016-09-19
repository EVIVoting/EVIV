package gsd.inescid.markpledge.smartclient.connection;

import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.markpledge.MarkPledgeType;
import gsd.inescid.markpledge.smartclient.apdu.GetAPDU;

import java.math.BigInteger;

public abstract class MP2And3AbstractBaseCardConnection extends MPAbstractCardConnection {

	protected MP2And3AbstractBaseCardConnection(int pLength, int qLength, int voteCodeLength, int chalLength,
			boolean showPerformanceTimes, ISmartCardInterface cardConnection, MarkPledgeType type) 
	{
		super(pLength, qLength, voteCodeLength, chalLength, showPerformanceTimes,
				cardConnection);
		this.MP_TYPE = type;
	}

	public BigInteger[] getVerificationCodeValidityFactors(int candidateIndex) 
			throws CardException 
	{
		byte[] apdu;
		GetAPDU.GET_VCODE_VALIDITY_FACTOR.setExpectedResponceLength(Q_LENGTH);
		GetAPDU.GET_VCODE_VALIDITY_FACTOR.setP1(candidateIndex);
		apdu = GetAPDU.GET_VCODE_VALIDITY_FACTOR.getAPDUBytes();
		return new BigInteger[]{new BigInteger(1, sendReceiveAPDU(apdu))};

	}

	public ElGamalEncryption[] getCandidateEncryption(int candidateIndex)
			throws CardException 
	{
		byte[] encX, encY;
		ElGamalEncryption[] candidateEncryption = new ElGamalEncryption[2];
		GetAPDU.GET_CANDIDATE_ENCRYPTION_X.setExpectedResponceLength(P_LENGTH);
		GetAPDU.GET_CANDIDATE_ENCRYPTION_Y.setExpectedResponceLength(P_LENGTH);
		// get first candidate ElGamalEncryption (vector X component in MP2 and be in MP3)
		GetAPDU.GET_CANDIDATE_ENCRYPTION_X.setP1(0);
		GetAPDU.GET_CANDIDATE_ENCRYPTION_Y.setP1(0);
		encX = sendReceiveAPDU(GetAPDU.GET_CANDIDATE_ENCRYPTION_X.getAPDUBytes());
		encY = sendReceiveAPDU(GetAPDU.GET_CANDIDATE_ENCRYPTION_Y.getAPDUBytes());
		candidateEncryption[0] = new ElGamalEncryption(encX, encY);
		// get second candidate ElGamal encryption (vector Y component in MP2 and ccode in MP3)
		GetAPDU.GET_CANDIDATE_ENCRYPTION_X.setP1(1);
		GetAPDU.GET_CANDIDATE_ENCRYPTION_Y.setP1(1);
		encX = sendReceiveAPDU(GetAPDU.GET_CANDIDATE_ENCRYPTION_X.getAPDUBytes());
		encY = sendReceiveAPDU(GetAPDU.GET_CANDIDATE_ENCRYPTION_Y.getAPDUBytes());
		candidateEncryption[1] = new ElGamalEncryption(encX, encY);
		return candidateEncryption;
	}
}
