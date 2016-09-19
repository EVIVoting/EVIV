package gsd.inescid.markpledge.smartclient.connection;

import java.math.BigInteger;

import gsd.inescid.markpledge.MarkPledgeType;
import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.mp2.interfaces.IMP2Parameters;
import gsd.inescid.markpledge.smartclient.CardConstants;
import gsd.inescid.markpledge.smartclient.CardUtil;
import gsd.inescid.markpledge.smartclient.apdu.SetAPDU;

public abstract class MP2AbstractCardConnection extends
		MP2And3AbstractBaseCardConnection {

	protected MP2AbstractCardConnection(int pLength, int qLength, int voteCodeLength, int chalLength, 
			boolean showPerformanceTimes, ISmartCardInterface cardConnection, MarkPledgeType type) 
	{
		super(pLength, qLength, voteCodeLength, chalLength, showPerformanceTimes, cardConnection,
				type);
	}
	
	public void setParameters(IMPParameters param) throws CardException{
		super.setParameters(param);
		IMP2Parameters mp2Param = (IMP2Parameters) param;
		BigInteger[][] so2qGenerator = mp2Param.getSO2qGenerator();
		byte[] apdu;
		apdu = SetAPDU.SET_MP2_GV_X.getAPDUBytes(CardUtil.bigIntegerToByteArray(so2qGenerator[0][0], Q_LENGTH));
		sendReceiveAPDU(apdu);
		apdu = SetAPDU.SET_MP2_GV_Y.getAPDUBytes(CardUtil.bigIntegerToByteArray(so2qGenerator[0][1], Q_LENGTH));
		sendReceiveAPDU(apdu);
		apdu = SetAPDU.SET_LAMBDA.getAPDUBytes(CardUtil.bigIntegerToByteArray(mp2Param.getLambda(), CardConstants.LAMBDA_LENGTH));
		sendReceiveAPDU(apdu);
		apdu = SetAPDU.SET_LAMBDA_MULTIPLIER.getAPDUBytes(CardUtil.bigIntegerToByteArray(mp2Param.getLambdaMultiplier(), Q_LENGTH));
		sendReceiveAPDU(apdu);
	}

}
