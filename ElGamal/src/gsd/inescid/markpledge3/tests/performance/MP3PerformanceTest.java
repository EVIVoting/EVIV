package gsd.inescid.markpledge3.tests.performance;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Random;

import gsd.inescid.crypto.ElGamalKeyPair;
import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.crypto.ElGamalPrivateKey;
import gsd.inescid.markpledge3.MP3AggregatedElectionVotes;
import gsd.inescid.markpledge3.MP3Parameters;
import gsd.inescid.markpledge3.MP3VoteAndReceipt;
import gsd.inescid.markpledge3.MP3VoteFactory;
import gsd.inescid.markpledge3.tests.TestKeysAndMP3Parameters;

public class MP3PerformanceTest {

	public static final int NUMBER_OF_VOTES = 1000;
	public static final int NUMBER_OF_CANDIDATES = 10;
	public static final String HASH_FUNCTION = "SHA-1";
	
	
	public static void main(String args[]) throws NoSuchAlgorithmException
	{
		SecureRandom r = new SecureRandom();
		
		boolean useDifferentGeneratorForTheMP3Parameter = false;
		long startVoteCreation, endVoteCreation, startVoteAggregationAndValidation,
			endVoteAggregationAndValidation, startTallyDecryption, endTallyDecryption, 
											startTallyTranslation, endTallyTranslation;
		
		
		// step 1 - get parameters (MP3 and keys)
		Object[] parameters = TestKeysAndMP3Parameters.getStaticKeyP1024G512();
		MP3Parameters mp3Param = (MP3Parameters) parameters[useDifferentGeneratorForTheMP3Parameter ? 2 : 1];
		ElGamalPrivateKey kpri = ((ElGamalKeyPair) parameters[0]).privateKey;
		
		// step 2 - create random votes
		System.out.println("Creating " + NUMBER_OF_VOTES + " random votes with " + NUMBER_OF_CANDIDATES + " candidates....");
		startVoteCreation = System.currentTimeMillis();
		Object[] preparedVotesAndResults = 
			createRandomVotes(NUMBER_OF_CANDIDATES, NUMBER_OF_VOTES, mp3Param, r, HASH_FUNCTION); 
		endVoteCreation = System.currentTimeMillis();
		MP3VoteAndReceipt[] votes = (MP3VoteAndReceipt[]) preparedVotesAndResults[0];
		
		// step 3 - validate and aggregate votes
		System.out.println("Validating and aggregating votes...");
		startVoteAggregationAndValidation = System.currentTimeMillis();
		MP3AggregatedElectionVotes electionVoteAggregation = 
			new MP3AggregatedElectionVotes(NUMBER_OF_CANDIDATES, votes, mp3Param, HASH_FUNCTION, true);
		endVoteAggregationAndValidation = System.currentTimeMillis();
		
		// step 4 - decrypt election results
		// step 4.1 - decrypt the candidates votes aggregation
		System.out.println("Decrypting the election tally...");
		startTallyDecryption = System.currentTimeMillis();
		BigInteger[] decryptedResults = decryptVotesAggregation(electionVoteAggregation, kpri);
		endTallyDecryption = System.currentTimeMillis();
		
		// step 4.2 - translate results
		// step 4.2.1 - create translation map
		startTallyTranslation = System.currentTimeMillis();
		HashMap<BigInteger,Integer> map = createDecodingMap(NUMBER_OF_VOTES, mp3Param);
		// step 4.2.2 - translate decrypted results
		int translatedResults[] = translateResults(decryptedResults, map, electionVoteAggregation.NUMBER_OF_AGGREGATED_VOTES);
		endTallyTranslation = System.currentTimeMillis();
		
		/*** verification and output of the results ***/
		int[] expectedResults = (int[])preparedVotesAndResults[1];
		verifyAndWriteResults(expectedResults, translatedResults);
		
		/*** output times ***/
		System.out.println("*************** MP3PerformanceTest Times ***************");
		System.out.println("Total number of votes: "+ NUMBER_OF_VOTES);
		System.out.println("Number of candidates: "+ NUMBER_OF_CANDIDATES);
		System.out.println("Votes creation time: " + (endVoteCreation - startVoteCreation));
		System.out.println("Validation and aggregation time: " + (endVoteAggregationAndValidation - startVoteAggregationAndValidation));
		System.out.println("Tally decryptiontime: " + (endTallyDecryption - startTallyDecryption));
		System.out.println("Tally translation time: " + (endTallyTranslation - startTallyTranslation));
		System.out.println("********************************************************");
	}
	
	
	public static void verifyAndWriteResults(int[] expectedResults, int[] results)
	{
		System.out.println("*** Election Results ***");
		char candidate = 'A';
		for(int i=0; i< results.length; i++, candidate++)
			System.out.println("Candidate " + candidate + ": " + expectedResults[i] + " - " + results[i] +
			                                            " " + (expectedResults[i]==results[i]));
		System.out.println("************************");
	}
	
	
	public static int[] translateResults(BigInteger[] decryptedResults, 
									HashMap<BigInteger, Integer> map, int numberOfAggregatedVotes)
	{
		int translatedResults[] = new int[decryptedResults.length];
		for(int i=0; i< translatedResults.length; i++)
			translatedResults[i] = (map.get(decryptedResults[i]) + numberOfAggregatedVotes) / 2;
		return translatedResults;
	}
	
	
	
	public static BigInteger[] decryptVotesAggregation(MP3AggregatedElectionVotes aggregatedVotes, ElGamalPrivateKey kpri)
	{
		ElGamalEncryption encryptedVotes[] = aggregatedVotes.aggregatedVotes;
		BigInteger results[] = new BigInteger[encryptedVotes.length]; // array with one position for each candidate
		
		for(int i=0; i<encryptedVotes.length; i++)
			results[i] = kpri.decryptQOrderMessage(encryptedVotes[i]);
		return results;
	}
	
	
	
	public static Object[] createRandomVotes(int numberOfCandidates, int numberOfVotes, 
			MP3Parameters mp3Param, Random r, String hashFunction) throws NoSuchAlgorithmException
	{
		MP3VoteFactory voteFactory = new MP3VoteFactory(mp3Param, hashFunction, r, true);
		MP3VoteAndReceipt votes[] = new MP3VoteAndReceipt[numberOfVotes];
		int finalVoteCount[] = new int[numberOfCandidates];
		int selectionIndex;
		
		
		for(int i=0; i<numberOfVotes; i++)
		{
			voteFactory.prepareVote(numberOfCandidates);
			selectionIndex = (int)(Math.random()*numberOfCandidates);
			votes[i] = voteFactory.getVoteAndReset(selectionIndex);
			finalVoteCount[selectionIndex]++;
		}
		
		return new Object[]{votes,finalVoteCount};
	}

	public static HashMap<BigInteger,Integer> createDecodingMap(int numberOfVotes, MP3Parameters mp3Param)
	{
		HashMap<BigInteger,Integer> map = new HashMap<BigInteger,Integer>((2*numberOfVotes)+1);
		BigInteger powers;
		
		map.put(BigInteger.ONE, 0);
		//positive values
		powers = mp3Param.BASE_VOTE_GENERATOR;
		map.put(powers, 1);
		for(int i=2; i<=numberOfVotes; i++)
		{
			powers = (powers.multiply(mp3Param.BASE_VOTE_GENERATOR)).mod(mp3Param.ELECTION_PUBLIC_KEY.p);
			map.put(powers, i);
		}
		
		//negative values
		powers = mp3Param.BASE_VOTE_GENERATOR_INVERSE;
		map.put(powers, -1);
		numberOfVotes = -numberOfVotes;
		for(int i=-2; i>=numberOfVotes; i--)
		{
			powers = (powers.multiply(mp3Param.BASE_VOTE_GENERATOR_INVERSE)).mod(mp3Param.ELECTION_PUBLIC_KEY.p);
			map.put(powers, i);
		}
			
		return map;
	}
}
