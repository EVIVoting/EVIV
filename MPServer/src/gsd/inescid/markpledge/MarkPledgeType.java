package gsd.inescid.markpledge;

import gsd.inescid.markpledge.smartclient.CardConstants;

public enum MarkPledgeType {
	MP1 			(CardConstants.BALLOT_TYPE_MP1),
	MP1A 			(CardConstants.BALLOT_TYPE_MP1A),
	MP2 			(CardConstants.BALLOT_TYPE_MP2),
	MP2_WITH_HELP	(CardConstants.BALLOT_TYPE_MP2_WITH_HELP),
	MP3 			(CardConstants.BALLOT_TYPE_MP3);
	
	private final int typeValue;
	
	private MarkPledgeType(int type)
	{
		this.typeValue = type;
	}
	
	public int getTypeValue()
	{
		return this.typeValue;
	}
}
