package gsd.inescid.markpledge3;

import java.math.BigInteger;

import gsd.inescid.crypto.ElGamalPublicKey;
import gsd.inescid.crypto.util.Base64;

public class MP3Parameters {
	public final ElGamalPublicKey ELECTION_PUBLIC_KEY;
	public final BigInteger BASE_VOTE_GENERATOR; // G
	public final BigInteger BASE_VOTE_GENERATOR_INVERSE; // G^-1
	
	// XML TAGS
	public static final String XML_TAG = "MP3Parameters";
	public static final String XML_BASE_GENERATOR_TAG = "BG";
	public static final String XML_BASE_GENERATOR_INVERSE_TAG = "BGI";
	
	public String toXML()
	{
		StringBuilder xml = new StringBuilder();
		xml.append("<" + XML_TAG + ">\n");
		xml.append(this.ELECTION_PUBLIC_KEY.toXML());
		xml.append("<" + XML_BASE_GENERATOR_TAG + ">" + Base64.encode(this.BASE_VOTE_GENERATOR.toByteArray()) + "</" + XML_BASE_GENERATOR_TAG + ">\n");
		xml.append("<" + XML_BASE_GENERATOR_INVERSE_TAG + ">" + Base64.encode(this.BASE_VOTE_GENERATOR_INVERSE.toByteArray()) + "</" + XML_BASE_GENERATOR_INVERSE_TAG + ">\n");
		xml.append("</" + XML_TAG + ">\n");
		return xml.toString();
	}

	
	public MP3Parameters(ElGamalPublicKey electionKey, BigInteger baseVoteGenerator)
	{
		this.ELECTION_PUBLIC_KEY = electionKey;
		//G = G^1
		this.BASE_VOTE_GENERATOR = baseVoteGenerator;
		//G^-1
		this.BASE_VOTE_GENERATOR_INVERSE = this.BASE_VOTE_GENERATOR.modPow(
				this.ELECTION_PUBLIC_KEY.q.subtract(BigInteger.ONE), 
				this.ELECTION_PUBLIC_KEY.p);
		
	}
	
		
	public String toString()
	{
		String s = "\nMarkPledge3 parameters\n" 
				 + this.ELECTION_PUBLIC_KEY 
				 + "\nG^1 = " + this.BASE_VOTE_GENERATOR 
				 + "\nG^-1= " + this.BASE_VOTE_GENERATOR_INVERSE;
		return s;
	}
	
	
	
}
