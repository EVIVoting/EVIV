package gsd.inescid.markpledge;

import java.util.Random;

import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.interfaces.IMPVoteReceiptFactory;
import gsd.inescid.markpledge.mp1.MP1VoteReceiptFactory;
import gsd.inescid.markpledge.mp1a.MP1AVoteReceiptFactory;
import gsd.inescid.markpledge.mp2.MP2Parameters;
import gsd.inescid.markpledge.mp2.MP2VoteReceiptFactory;
import gsd.inescid.markpledge.mp3.MP3VoteReceiptFactory;
import gsd.inescid.markpledge.MarkPledgeType;


public class MPVoteReceiptFactory {

	public static IMPVoteReceiptFactory getInstance(MarkPledgeType type, IMPParameters param, Random randomSource)
	{
		switch(type)
		{
			case MP1:
				return new MP1VoteReceiptFactory(param, randomSource);
			case MP1A:
				return new MP1AVoteReceiptFactory(param, randomSource);
			case MP2:
				return new MP2VoteReceiptFactory((MP2Parameters)param, randomSource);
			case MP3:
				return new MP3VoteReceiptFactory(param, randomSource);
			default:
				return null;
		}
	}
}
