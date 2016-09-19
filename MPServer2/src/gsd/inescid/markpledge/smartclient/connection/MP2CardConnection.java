package gsd.inescid.markpledge.smartclient.connection;

import gsd.inescid.markpledge.MarkPledgeType;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;
import gsd.inescid.markpledge.smartclient.apdu.ActionAPDU;

public class MP2CardConnection extends MP2AbstractCardConnection {
	
	public MP2CardConnection(int pLength, int qLength, int voteCodeLength, int chalLength,
			boolean showPerformanceTimes, ISmartCardInterface cardConnection) 
	{
		super(pLength, qLength, voteCodeLength, chalLength, showPerformanceTimes, cardConnection,
				MarkPledgeType.MP2);
	}
	
	public IMPValidityProof getValidity(int numberOfCandidates) throws CardException
	{
		long start, end;
		//create canonical vote
		start = System.currentTimeMillis();
		sendReceiveAPDU(ActionAPDU.CREATE_MP2_CANONICAL_VOTE.getAPDUBytes(null));
		end = System.currentTimeMillis();
		if(PERFORMANCE_TIMES)
			System.out.println("Canonical vote transformation: " + (end-start));
		
		return super.getValidity(numberOfCandidates); 
	}
	
	
}
