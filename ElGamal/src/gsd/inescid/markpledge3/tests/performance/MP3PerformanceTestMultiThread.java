package gsd.inescid.markpledge3.tests.performance;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Random;

import gsd.inescid.crypto.ElGamalKeyPair;
import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.crypto.ElGamalPrivateKey;
import gsd.inescid.crypto.ElGamalVerifiableEncryption;
import gsd.inescid.markpledge3.MP3AggregatedElectionVotes;
import gsd.inescid.markpledge3.MP3CandidateVoteEncryption;
import gsd.inescid.markpledge3.MP3Parameters;
import gsd.inescid.markpledge3.MP3VoteAndReceipt;
import gsd.inescid.markpledge3.MP3VoteFactory;
import gsd.inescid.markpledge3.tests.TestKeysAndMP3Parameters;

public class MP3PerformanceTestMultiThread implements Runnable{

	public static final int DEFAULT_NUMBER_OF_VOTES = 10;
	public static final int DEFAULT_NUMBER_OF_CANDIDATES = 2;
	public static final int DEFAULT_NUMBER_OF_THREADS = 1;
	
	public static int NUMBER_OF_VOTES;
	public static int NUMBER_OF_CANDIDATES;
	
	
	public static final int WAIT_TIME = 5000;
	public static final String HASH_FUNCTION = "SHA-1";

	private static MP3AggregatedElectionVotes[] aggregatedVotes;
	private static int[][] expectedResults;
	
	private static PrintStream mainOutput;
	
	private static int identifiers = -1;
	
	public static synchronized int getIdentifier(){
		identifiers ++;
		return identifiers;
	}
	
	public void run()
	{
		PrintStream output = null;
		try{
			int threadIdentifier = getIdentifier();
			output = new PrintStream(new FileOutputStream("ResultsThread" + threadIdentifier + ".txt"));

			SecureRandom r = new SecureRandom();
			boolean useDifferentGeneratorForTheMP3Parameter = false;
			long startVoteCreation, endVoteCreation, startVoteAggregationAndValidation,
			endVoteAggregationAndValidation, startVoteReceiptValidation, endVoteReceiptValidation,
			startVoteAggregation, endVoteAggregation;


			// step 1 - get parameters (MP3 and keys)
			Object[] parameters = TestKeysAndMP3Parameters.getStaticKeyP1024G512();
			MP3Parameters mp3Param = (MP3Parameters) parameters[useDifferentGeneratorForTheMP3Parameter ? 2 : 1];
			
			//  a kit-kat break :)
			Thread.sleep(WAIT_TIME);
			
			// step 2 - create random votes
			println("Creating " + NUMBER_OF_VOTES + " random votes with " + NUMBER_OF_CANDIDATES + " candidates....", output);
			startVoteCreation = System.currentTimeMillis();
			Object[] preparedVotesAndResults = 
				createRandomVotes(NUMBER_OF_CANDIDATES, NUMBER_OF_VOTES, mp3Param, r, HASH_FUNCTION); 
			endVoteCreation = System.currentTimeMillis();
			MP3VoteAndReceipt[] votes = (MP3VoteAndReceipt[]) preparedVotesAndResults[0];
			
			// step 3 - set expected results
			expectedResults[threadIdentifier] = (int[])preparedVotesAndResults[1];
			
			// step 3 - validate and aggregate votes
			println("Validating and aggregating votes...", output);
			startVoteAggregationAndValidation = System.currentTimeMillis();
			MP3AggregatedElectionVotes electionVoteAggregation = 
				new MP3AggregatedElectionVotes(NUMBER_OF_CANDIDATES, votes, mp3Param, HASH_FUNCTION, true);
			endVoteAggregationAndValidation = System.currentTimeMillis();

			// step 4 - set aggregation results
			aggregatedVotes[threadIdentifier] = electionVoteAggregation;
			
			// step 5 - validate receipt only
			println("Validating receipts...", output);
			startVoteReceiptValidation = System.currentTimeMillis();
			verifyReceiptOnly(NUMBER_OF_CANDIDATES, votes, mp3Param);
			endVoteReceiptValidation = System.currentTimeMillis();
			
			// step 6 - aggregate votes only
			println("Aggregating votes...", output);
			startVoteAggregation = System.currentTimeMillis();
			aggregateOnly(NUMBER_OF_CANDIDATES, votes, mp3Param);
			endVoteAggregation = System.currentTimeMillis();
			
			
			
			/*** output times ***/
			println("*************** MP3PerformanceTestMultiThread Times ***************", output);
			println("Total number of votes: "+ NUMBER_OF_VOTES, output);
			println("Number of candidates: "+ NUMBER_OF_CANDIDATES, output);
			println("Votes creation time: " + (endVoteCreation - startVoteCreation), output);
			println("Validation and aggregation time: " + (endVoteAggregationAndValidation - startVoteAggregationAndValidation), output);
			println("Validate receipt time: " + (endVoteReceiptValidation - startVoteReceiptValidation), output);
			println("Aggregation time: " + (endVoteAggregation - startVoteAggregation), output);
			println("********************************************************", output);
			
			output.close();
			
		}catch(Exception e)
		{
			println(e.getMessage(), output);
			e.printStackTrace();
		}
		
	}

	public static void println(String m, PrintStream output)
	{
		output.println(m);
		//println(m);
	}
	
	public static void main(String args[]) throws NoSuchAlgorithmException, InterruptedException, FileNotFoundException
	{	
		boolean useDifferentGeneratorForTheMP3Parameter = false;
		long startVoteAggregation, endVoteAggregation, startTallyDecryption, endTallyDecryption, 
		startTallyTranslation, endTallyTranslation;

		mainOutput = new PrintStream(new FileOutputStream("MainResults.txt"));

		//step 0 prepare parameters
		int NUMBER_OF_THREADS;
		try{
			NUMBER_OF_VOTES = Integer.valueOf(args[0]);
			NUMBER_OF_CANDIDATES = Integer.valueOf(args[1]);
			NUMBER_OF_THREADS = Integer.valueOf(args[2]);
		} catch (Exception e)
		{
			NUMBER_OF_VOTES = DEFAULT_NUMBER_OF_VOTES;
			NUMBER_OF_CANDIDATES = DEFAULT_NUMBER_OF_CANDIDATES;
			NUMBER_OF_THREADS = DEFAULT_NUMBER_OF_THREADS;	
		}
		
		println("Test with " + NUMBER_OF_THREADS + " threads.", mainOutput);
		println("Test with " + NUMBER_OF_VOTES + " votes per thread.", mainOutput);	 
		println("Test with " + NUMBER_OF_CANDIDATES + " candidates per vote.", mainOutput);
		
		
		

		// step 1 - get parameters (MP3 and keys)
		Object[] parameters = TestKeysAndMP3Parameters.getStaticKeyP1024G512();
		MP3Parameters mp3Param = (MP3Parameters) parameters[useDifferentGeneratorForTheMP3Parameter ? 2 : 1];
		ElGamalPrivateKey kpri = ((ElGamalKeyPair) parameters[0]).privateKey;

		// step 2 - prepare and start threads
				
		aggregatedVotes = new MP3AggregatedElectionVotes[NUMBER_OF_THREADS];
		expectedResults = new int[NUMBER_OF_THREADS][];
		
		Thread threads[] = new Thread[NUMBER_OF_THREADS];
		for(int i=0; i < threads.length; i++)
		{
			threads[i] = new Thread(new MP3PerformanceTestMultiThread());
			threads[i].start();
		}
		
		// step 3 wait for all threads to end
		for(int i=0; i < threads.length; i++)
		{
			threads[i].join();
		}
		
		// step 4 - join aggregated votes
		startVoteAggregation = System.currentTimeMillis();
		
		ElGamalEncryption tallyAggregation[] = new ElGamalEncryption[NUMBER_OF_CANDIDATES];
		int expectedAggregationResults[] = new int[NUMBER_OF_CANDIDATES];
		                                 
		for(int i=0; i<NUMBER_OF_CANDIDATES; i++)
		{
			tallyAggregation[i] = aggregatedVotes[0].aggregatedVotes[i];
			expectedAggregationResults[i] = expectedResults[0][i];
		}
		
		for(int j=1; j<NUMBER_OF_THREADS; j++)
		{
			for(int i=0; i<NUMBER_OF_CANDIDATES; i++)
			{
				tallyAggregation[i] = tallyAggregation[i].multiply(aggregatedVotes[j].aggregatedVotes[i], kpri.p);
				expectedAggregationResults[i] = expectedAggregationResults[i] + expectedResults[j][i];
			}
		}
				
		endVoteAggregation = System.currentTimeMillis();

		
		

		// step 4 - decrypt election results
		// step 4.1 - decrypt the candidates votes aggregation
		startTallyDecryption = System.currentTimeMillis();
		BigInteger[] decryptedResults = decryptVotesAggregation(tallyAggregation, kpri);
		endTallyDecryption = System.currentTimeMillis();

		// step 4.2 - translate results
		// step 4.2.1 - create translation map
		startTallyTranslation = System.currentTimeMillis();
		HashMap<BigInteger,Integer> map = createDecodingMap(NUMBER_OF_VOTES * NUMBER_OF_THREADS, mp3Param);
		// step 4.2.2 - translate decrypted results
		int translatedResults[] = translateResults(decryptedResults, map, NUMBER_OF_VOTES * NUMBER_OF_THREADS);
		endTallyTranslation = System.currentTimeMillis();

		/*** verification and output of the results ***/
		verifyAndWriteResults(expectedAggregationResults, translatedResults);

		/*** output times ***/
		println("*************** MP3PerformanceTest Times ***************", mainOutput);
		println("Total number of votes: "+ NUMBER_OF_VOTES * NUMBER_OF_THREADS, mainOutput);
		println("Number of candidates: "+ NUMBER_OF_CANDIDATES, mainOutput);
		println("Final aggregation time: " + (endVoteAggregation - startVoteAggregation), mainOutput);
		println("Tally decryption time: " + (endTallyDecryption - startTallyDecryption), mainOutput);
		println("Tally translation time: " + (endTallyTranslation - startTallyTranslation), mainOutput);
		println("********************************************************", mainOutput);
	}


	public static void verifyAndWriteResults(int[] expectedResults, int[] results)
	{
		println("*** Election Results ***", mainOutput);
		char candidate = 'A';
		for(int i=0; i< results.length; i++, candidate++)
			println("Candidate " + candidate + ": " + expectedResults[i] + " - " + results[i] +
					" " + (expectedResults[i]==results[i]), mainOutput);
		println("************************", mainOutput);
	}


	public static int[] translateResults(BigInteger[] decryptedResults, 
			HashMap<BigInteger, Integer> map, int numberOfAggregatedVotes)
	{
		int translatedResults[] = new int[decryptedResults.length];
		for(int i=0; i< translatedResults.length; i++)
			translatedResults[i] = (map.get(decryptedResults[i]) + numberOfAggregatedVotes) / 2;
		return translatedResults;
	}



	public static BigInteger[] decryptVotesAggregation(ElGamalEncryption encryptedVotes[], ElGamalPrivateKey kpri)
	{
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
	
	
	// UTILITY methods
	public static void verifyReceiptOnly(int numberOfCandidates, MP3VoteAndReceipt[] votes, 
			MP3Parameters mp3Param) throws Exception
			{
		ElGamalVerifiableEncryption chalEncryption;
		MP3VoteAndReceipt vote;
		MP3CandidateVoteEncryption cvote, cvotes[];
		BigInteger verificationMessage;
				
		for(int i=0; i<votes.length; i++)
		{
			vote = votes[i];
			cvotes = vote.CANDIDATE_VOTES;
			
			//create the message in the q-order subgroup of Z*_p that corresponds to the exponential challenge encryption 
			verificationMessage = mp3Param.BASE_VOTE_GENERATOR.modPow(vote.CHALLENGE, mp3Param.ELECTION_PUBLIC_KEY.p);
			
			// verification of the cvotes
			for(int j=0; j < numberOfCandidates; j++)
			{
				cvote = cvotes[j];
				// step 1 - get validation data
				chalEncryption = cvote.getVerifiableEncryption(vote.CHALLENGE, 
						mp3Param.ELECTION_PUBLIC_KEY.p, mp3Param.ELECTION_PUBLIC_KEY.q);
				// step 2 - verify the chal encryption
				if(!mp3Param.ELECTION_PUBLIC_KEY.verifyQOrderMessageEncryption(verificationMessage, chalEncryption))
				{
					println("cvote verification fail: " + j, mainOutput);
					throw new Exception("cvote verification failed");
				}	
			}

		}
	}

	public static void aggregateOnly(int numberOfCandidates, MP3VoteAndReceipt[] votes, 
			MP3Parameters mp3Param)
	{
		ElGamalEncryption voteAggregation[] = new ElGamalEncryption[numberOfCandidates];
		MP3VoteAndReceipt vote;
		MP3CandidateVoteEncryption cvotes[];
		
		/*** vote aggregation initialization ***/
		for(int i=0; i < voteAggregation.length; i++)
			voteAggregation[i] = new ElGamalEncryption(BigInteger.ONE, BigInteger.ONE);

		for(int i=0; i<votes.length; i++)
		{
			vote = votes[i];
			cvotes = vote.CANDIDATE_VOTES;
	
			/*** aggregateVote ***/
				for(int k=0, v=vote.FIRST_CANDIDATE_INDEX; k < voteAggregation.length; k++, v=(++v%numberOfCandidates))
					voteAggregation[k] = voteAggregation[k].multiply(cvotes[v].BIT_ENCRYPTION, mp3Param.ELECTION_PUBLIC_KEY.p);
		}
	}
}
