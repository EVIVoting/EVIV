package gsd.inescid.markpledge3;

import java.math.BigInteger;

import gsd.inescid.crypto.ElGamalPublicKey;
import gsd.inescid.crypto.util.Base64;

public class MP3Parameters {
	public final ElGamalPublicKey ELECTION_PUBLIC_KEY;
	public final BigInteger BASE_VOTE_GENERATOR; // G
	public final BigInteger BASE_VOTE_GENERATOR_INVERSE; // G^-1
	
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
