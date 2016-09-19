package gsd.inescid.markpledge.demo.server;

import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.crypto.ElGamalPrivateKey;
import gsd.inescid.markpledge.MPEncryptedVote;
import gsd.inescid.markpledge.MPKeyAndParameters;
import gsd.inescid.markpledge.MPUtil;
import gsd.inescid.markpledge.MPVoteReceiptFactory;
import gsd.inescid.markpledge.MarkPledgeType;
import gsd.inescid.markpledge.interfaces.IMPEncryptedVote;
import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.interfaces.IMPReceipt;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;
import gsd.inescid.markpledge.interfaces.IMPVoteAndReceipt;
import gsd.inescid.markpledge.interfaces.IMPVoteReceiptFactory;
import gsd.inescid.markpledge.smartclient.CardConstants;
import gsd.inescid.markpledge.smartclient.CardUtil;
import gsd.inescid.markpledge.smartclient.connection.CardException;
import gsd.inescid.markpledge.smartclient.connection.IMPCardConnection;
import gsd.inescid.markpledge.smartclient.connection.ISmartCardInterface;
import gsd.inescid.markpledge.smartclient.connection.MultosCOMCardInterface;
import gsd.inescid.markpledge3.MP3AggregatedElectionVotes;
import gsd.inescid.markpledge3.MP3Parameters;
import gsd.inescid.markpledge3.MP3VoteAndReceipt;
import gsd.inescid.markpledge3.tests.TestKeysAndMP3Parameters;
import gsd.inescid.markpledge3.tests.performance.MP3PerformanceTestMultiThread;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Random;

import com.sun.java.swing.plaf.motif.MotifPasswordFieldUI;

public class ServerPerformance implements Runnable{
	

	/*************************************************************************************/
	/*************************************************************************************/
	/*************************************************************************************/
	/*************************************************************************************/
	
	static boolean withValidityProof = true;
	static boolean sameGenerator = false;
	static boolean staticKey = true;
	
	static int numberOfVotes = 1000;
	static int numberOfCandidates = 10;
	static MarkPledgeType ballotType = MarkPledgeType.MP3;
	static int pLength = 1024;
	static int qLength = 160;
	static int alpha = 24;
	static IMPParameters param;
	static ElGamalPrivateKey kpri;
	static int waitTime = 2000;
	static int numberOfThreads = 1;
	
	public static void main(String[] args) throws NoSuchAlgorithmException, InterruptedException
	{
		if(args.length != 6)
		{
			System.out.println("Running with default parameters.");
			System.out.println("MP3 p=1024 q=160 nVotes=1000 nCandidates=10 nThreads=1");
		}
		else
		{
			try{
				ballotType = MarkPledgeType.valueOf(args[0]);
				pLength = Integer.parseInt(args[1]);
				qLength = Integer.parseInt(args[2]);
				numberOfVotes = Integer.parseInt(args[3]);
				numberOfCandidates = Integer.parseInt(args[4]);
				numberOfThreads = Integer.parseInt(args[5]);
				staticKey = false;
			} catch(Exception e)
			{
				System.out.println("Error in parameters.");
				System.out.println("<MPType> <pLength> <qLength> <nVotes> <nCandidates> <nThreads>");
				System.exit(-1);
			}
		}
		
		
		
		
		MPKeyAndParameters keyAndParam;
		if(staticKey)
			keyAndParam = MPUtil.generateStaticKeyAndParameters(pLength, qLength, alpha, ballotType, sameGenerator);
		else
			keyAndParam = MPUtil.generateKeyAndParameters(pLength, qLength, alpha, ballotType, sameGenerator);
	
		param = keyAndParam.MP_PARAMETERS;
		param.setVoteCodeByteLength(CardConstants.CANDIDATE_CODE_LENGTH);
		
		kpri = keyAndParam.KEY_PAIR.privateKey;

		
		Thread threads[] = new Thread[numberOfThreads];
		for(int i=0; i < threads.length; i++)
		{
			threads[i] = new Thread(new ServerPerformance());
			threads[i].start();
		}
		
		// wait for all threads to end
		for(int i=0; i < threads.length; i++)
		{
			threads[i].join();
		}
		
	}
	
	private static int identifiers = -1;
	public static synchronized int getIdentifier(){
		identifiers ++;
		return identifiers;
	}
	
	
	PrintStream out = System.out;
	public void run()
	{
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			Random randomness = new SecureRandom();
			
			int threadIdentifier = getIdentifier();
			println("Thread " + threadIdentifier);
			
			out = new PrintStream(new FileOutputStream("ResultsThread" + threadIdentifier + ".txt"));
			
			println("Thread " + threadIdentifier);
						
			//  kit-kat break :)
			Thread.sleep(waitTime);


			IMPVoteAndReceipt[] votes = createVotesAndReceipt(numberOfVotes, ballotType, numberOfCandidates,
					param, randomness, withValidityProof);

			verifyVotesAndReceipt(votes, numberOfCandidates, param, md);
			int[] rHomomorphic = homomorphicVoteTallyDecryption(votes, numberOfCandidates, param, kpri);
			int[] rDecryption = decryptAllVotes(votes, numberOfCandidates, param, kpri);

			println("Vote tally (homomorphic and by individual decryption):");
			println(Arrays.toString(rHomomorphic));
			println(Arrays.toString(rDecryption));

			System.out.close();

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public void println(String m)
	{
		out.println(m);
	}

	
	/*************************************************************************************/
	/*************************************************************************************/
	/*************************************************************************************/
	/*************************************************************************************/

	
	public IMPVoteAndReceipt[] createVotesAndReceipt(
			int numberOfVotes, MarkPledgeType mpType, int numberOfCandidates, 
			IMPParameters param, Random randomSource, boolean withValidity)
		{
			IMPVoteReceiptFactory factory = MPVoteReceiptFactory.getInstance(mpType, param, randomSource);
			IMPVoteAndReceipt[] votes = new IMPVoteAndReceipt[numberOfVotes];
			
			long start = System.currentTimeMillis();
			/**********/
			for(int i=0; i<numberOfVotes; i++)
			{
				votes[i] = factory.getNewVoteAndReceipt(withValidity, numberOfCandidates);
			}
			/***********/
			long end = System.currentTimeMillis();
			long time = end-start;
			
			println("\nVote and receipt creation ");
			if(withValidity)
				println("with validity");
			else
				println("without validity");
			
			println("votes:      " + numberOfVotes);
			println("candidates: " + numberOfCandidates);
			println("Total time in ms    : " + time);
			println("Individual vote time: " + time / numberOfVotes);
			println("Individual cand time: " + time / numberOfVotes / numberOfCandidates);
			
			return votes;
		}
		
		
		public void verifyVotesAndReceipt(
				IMPVoteAndReceipt[] votes, int numberOfCandidates, 
				IMPParameters param, MessageDigest md)
		{
			long start = System.currentTimeMillis();
			/**********/
			for(int i=0; i< votes.length; i++)
			{
				votes[i].verifyAll(param, 1, md);
			}
			/**********/
			long end = System.currentTimeMillis();
			long time = end-start;
			
			println("\nVote and receipt verification");
			println("Total time in ms    : " + time);
			println("Individual vote time: " + time / votes.length);
			println("Individual cand time: " + time / votes.length / numberOfCandidates);

			
		}
		
		
		public int[] homomorphicVoteTallyDecryption(
				IMPVoteAndReceipt[] votes, int numberOfCandidates, 
				IMPParameters param, ElGamalPrivateKey kpri)
		{
			ElGamalEncryption[] homomorphicAggregation = new ElGamalEncryption[numberOfCandidates];
			for(int i=0; i< homomorphicAggregation.length; i++)
				homomorphicAggregation[i] = new ElGamalEncryption(BigInteger.ONE, BigInteger.ONE);
			
			BigInteger p = param.getP();
			
			//compute vote tally aggregation
			long start = System.currentTimeMillis();
			for(int i=0; i<votes.length; i++)
			{
				ElGamalEncryption[] vote = votes[i].getCanonicalVote(param);
				
				for(int k=0; k<numberOfCandidates; k++)
					homomorphicAggregation[k] = vote[k].multiply(homomorphicAggregation[k], p);
			}
			long end = System.currentTimeMillis();
			
			println("\nHomomorphic aggregation: " + (end-start));
			
			//decrypt vote tally aggregation
			BigInteger aux;
			BigInteger mpG = param.getMP_G();
			BigInteger q = param.getQ();
			BigInteger positiveResult, negativeResult;
			
			int maxVotes = votes.length;
			int[] results = new int[numberOfCandidates];
			int k;
			start = System.currentTimeMillis();
			//build decryption hashMap
			HashMap<BigInteger, Integer> map = createDecodingMap(votes.length, param);
			end = System.currentTimeMillis();
			println("Homomorphic tally decryption (create decryption map): " + (end-start));
			
			start = System.currentTimeMillis();
			for(int i=0; i<numberOfCandidates; i++)
			{
				//decrypt candidate aggregation
				aux = kpri.decryptQOrderMessage(homomorphicAggregation[i]);
				//"decode" decryption result
				results[i] = (map.get(aux) + votes.length) /2;
			}
			end = System.currentTimeMillis();
			println("Homomorphic tally decryption: " + (end-start));
			
			return results;
		}
		
		
		public  int[] decryptAllVotes(
				IMPVoteAndReceipt[] votes, int numberOfCandidates, 
				IMPParameters param, ElGamalPrivateKey kpri)
		{
			
			int[] totalResults = new int[numberOfCandidates];
			long start = System.currentTimeMillis();
			for(int i=0; i<votes.length; i++)
			{
				IMPVoteAndReceipt vote = votes[i];
				int[] aux = MPUtil.decryptedCanonicalVote(vote.getCanonicalVote(param), 
						kpri, param, 0);
				
				for(int k=0; k<numberOfCandidates; k++)
					if(aux[k]==1)
						totalResults[k]++;
			}
			long end = System.currentTimeMillis();
			println("\nTotal individual decryption time: " + (end-start));
			
			return totalResults;
		}
		
		
		public static HashMap<BigInteger,Integer> createDecodingMap(int numberOfVotes, IMPParameters param)
		{
			HashMap<BigInteger,Integer> map = new HashMap<BigInteger,Integer>((2*numberOfVotes)+1);
			BigInteger powers, mpG, mpGInv, p;
			
			p = param.getP();
			map.put(BigInteger.ONE, 0);
			//positive values
			powers = param.getMP_G();
			mpG = powers;
			map.put(powers, 1);
			for(int i=2; i<=numberOfVotes; i++)
			{
				powers = (powers.multiply(mpG)).mod(p);
				map.put(powers, i);
			}
			
			//negative values
			powers = param.getMP_GInv();
			mpGInv = powers;
			map.put(powers, -1);
			numberOfVotes = -numberOfVotes;
			for(int i=-2; i>=numberOfVotes; i--)
			{
				powers = (powers.multiply(mpGInv)).mod(p);
				map.put(powers, i);
			}
				
			return map;
		}
		
		
	
	
}
