package gsd.inescid.markpledge.smartclient.connection;

import gsd.inescid.markpledge.MarkPledgeType;

public class MP3CardConnection extends MP2And3AbstractBaseCardConnection {

	public MP3CardConnection(int pLength, int qLength, int voteCodeLength, int chalLength,
			boolean showPerformanceTimes, ISmartCardInterface cardConnection) 
	{
		super(pLength, qLength, voteCodeLength, chalLength, showPerformanceTimes, cardConnection,
				MarkPledgeType.MP3);
	}

}
