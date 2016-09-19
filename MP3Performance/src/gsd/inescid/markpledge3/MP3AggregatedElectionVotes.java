package gsd.inescid.markpledge3;

import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.crypto.ElGamalVerifiableEncryption;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MP3AggregatedElectionVotes {

	/** 
	 * Number of aggregated votes. 
	 * If the vote validation is turn of all votes are aggregated.
	 **/
	public final int NUMBER_OF_AGGREGATED_VOTES;
	public final int INVALID_VOTES;
	public final ElGamalEncryption[] aggregatedVotes;

	/**
	 * This constructor validates and aggregates an array of MP3 votes.
	 *  
	 * @param numberOfCandidates number of candidates in the election
	 * @param votes the votes to be validated and aggregated
	 * @param mp3Param the MP3 parameters used in the vote creation
	 * @param hashFunction the hash function that was used in the CGS97 validity proof creation
	 * @throws NoSuchAlgorithmException 
	 */
	public MP3AggregatedElectionVotes(int numberOfCandidates, MP3VoteAndReceipt[] votes, 
			MP3Parameters mp3Param, String hashFunction) throws NoSuchAlgorithmException
			{
		MessageDigest md = MessageDigest.getInstance(hashFunction);
		ElGamalEncryption voteAggregation[] = new ElGamalEncryption[numberOfCandidates];
		ElGamalEncryption cvotesAggregation;
		ElGamalVerifiableEncryption chalEncryption, verifiableCvotesAggregation;
		MP3VoteAndReceipt vote;
		MP3CandidateVoteEncryption cvote, cvotes[];
		BigInteger verificationMessage;
		BigInteger expectedVoteVerificationResult = BigInteger.valueOf(2 - numberOfCandidates);
		int invalidVotes = 0;

		/*** vote aggregation initialization ***/
		for(int i=0; i < voteAggregation.length; i++)
			voteAggregation[i] = new ElGamalEncryption(BigInteger.ONE, BigInteger.ONE);

		for(int i=0; i<votes.length; i++)
		{
			vote = votes[i];
			cvotes = vote.CANDIDATE_VOTES;
			try{


				//init cvotes aggregation
				cvotesAggregation = new ElGamalEncryption(BigInteger.ONE, BigInteger.ONE);

				/*** verify individual candidate votes validity and receipt correctness ***/
				//create the message in the q-order subgroup of Z*_p that corresponds to the exponential challenge encryption 
				verificationMessage = mp3Param.BASE_VOTE_GENERATOR.modPow(vote.CHALLENGE, mp3Param.ELECTION_PUBLIC_KEY.p);
				for(int j=0; j < numberOfCandidates; j++)
				{
					cvote = cvotes[j];
					// step 1 - verify be validity
					if(!CGS97BallotValidity.verifyBallotValidity(cvote.BIT_ENCRYPTION,
							cvote.BIT_ENCRYPTION_VALIDITY, 
							mp3Param.ELECTION_PUBLIC_KEY, 
							mp3Param.BASE_VOTE_GENERATOR, 
							mp3Param.BASE_VOTE_GENERATOR_INVERSE, md))
					{
						System.out.println("CGS97 verification fail: " + j);
						throw new Exception("be not valid");
					}


					// step 2 verification of the cvote 
					// step 2.1 - get validation data
					chalEncryption = cvote.getVerifiableEncryption(vote.CHALLENGE, 
							mp3Param.ELECTION_PUBLIC_KEY.p, mp3Param.ELECTION_PUBLIC_KEY.q);
					// step 2.2 - verify the chal encryption
					if(!mp3Param.ELECTION_PUBLIC_KEY.verifyQOrderMessageEncryption(verificationMessage, chalEncryption))
					{
						System.out.println("cvote verification fail: " + j);
						throw new Exception("cvote verification failed");
					}	

					//aggregate cvote for vote validity check below
					cvotesAggregation = cvotesAggregation.multiply(cvote.BIT_ENCRYPTION, mp3Param.ELECTION_PUBLIC_KEY.p);

				}

				/*** verify vote validity (cvotes aggregation ***/
				// step 1 - expected result calculus
				verificationMessage = mp3Param.BASE_VOTE_GENERATOR.modPow(expectedVoteVerificationResult, mp3Param.ELECTION_PUBLIC_KEY.p);
				// step 2 - verify cvotes aggregated encryption
				verifiableCvotesAggregation = new ElGamalVerifiableEncryption(cvotesAggregation, vote.VOTE_VALIDITY);
				if(!mp3Param.ELECTION_PUBLIC_KEY.verifyQOrderMessageEncryption(verificationMessage, verifiableCvotesAggregation))
					throw new Exception("aggregate cvotes verification failed");					


				/*** aggregateVote ***/
				for(int k=0, v=vote.FIRST_CANDIDATE_INDEX; k < voteAggregation.length; k++, v=(++v%numberOfCandidates))
					voteAggregation[k] = voteAggregation[k].multiply(cvotes[v].BIT_ENCRYPTION, mp3Param.ELECTION_PUBLIC_KEY.p);


			} catch (Exception e)
			{
				System.out.println("Vote " + i + " is invalid: " + e.getMessage());
				invalidVotes++;
			}
		}
		this.aggregatedVotes = voteAggregation;
		this.INVALID_VOTES = invalidVotes;
		this.NUMBER_OF_AGGREGATED_VOTES = votes.length - this.INVALID_VOTES;
	}
}
