package gsd.inescid.markpledge;

import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.interfaces.IMPVoteReceiptFactory;
import gsd.inescid.markpledge.mp1.MP1VoteReceiptFactory;
import gsd.inescid.markpledge.mp1a.MP1AVoteReceiptFactory;
import gsd.inescid.markpledge.mp2.MP2Parameters;
import gsd.inescid.markpledge.mp2.MP2VoteReceiptFactory;
import gsd.inescid.markpledge.mp3.MP3VoteReceiptFactory;

import java.security.MessageDigest;
import java.util.Random;


public class MPVoteReceiptFactory {

	public static IMPVoteReceiptFactory getInstance(MarkPledgeType type, IMPParameters param)
	{
		switch(type)
		{
			case MP1:
				return new MP1VoteReceiptFactory(param);
			case MP1A:
				return new MP1AVoteReceiptFactory(param);
			case MP2:
				return new MP2VoteReceiptFactory((MP2Parameters)param);
			case MP3:
				return new MP3VoteReceiptFactory(param);
			default:
				return null;
		}
	}
}
