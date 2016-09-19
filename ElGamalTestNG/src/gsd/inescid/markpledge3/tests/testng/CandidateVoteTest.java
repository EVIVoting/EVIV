package gsd.inescid.markpledge3.tests.testng;

import gsd.inescid.crypto.ElGamalKeyPair;
import gsd.inescid.crypto.ElGamalPrivateKey;
import gsd.inescid.crypto.ElGamalPublicKey;
import gsd.inescid.crypto.util.CryptoUtil;
import gsd.inescid.markpledge3.MP3CandidateVoteEncryption;
import gsd.inescid.markpledge3.MP3Parameters;
import gsd.inescid.markpledge3.MP3PreparedCandidateVote;
import gsd.inescid.markpledge3.tests.TestKeysAndMP3Parameters;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class CandidateVoteTest {
	public static final String TEST_HASH_FUNCTION = "SHA-1";


	@DataProvider(name = "staticKeyProvider")
	public Object[][] getStaticKeysAndMP3ParametersForTesting(){
		SecureRandom r = new SecureRandom();
		Object[][] testParameters = TestKeysAndMP3Parameters.getStaticKeysAndMP3Parameters();
		Object[][] result = new Object[testParameters.length * 2][];
		
		String description;
		
		for(int i=0, resultIndex=0; i< testParameters.length; i++)
		{
			description = "static test key (p=" + TestKeysAndMP3Parameters.TEST_KEY_SIZES[i][0] +
										  " q=" + TestKeysAndMP3Parameters.TEST_KEY_SIZES[i][0] + ") ";
			result[resultIndex++] = new Object[] {description + " same generator" , testParameters[i][0], testParameters[i][1], r};
			result[resultIndex++] = new Object[] {description + " new generator" , testParameters[i][0], testParameters[i][2], r};
		}
		
		return result;
	}

	@DataProvider(name = "newKeyProvider")
	public Object[][] createNewKeysAndMP3ParametersForTesting(){
		try {
			SecureRandom r = new SecureRandom();
			Object[][] testParameters = TestKeysAndMP3Parameters.generateNewKeysAndMP3Parameters(
					TestKeysAndMP3Parameters.TEST_KEY_SIZES);
			Object[][] result = new Object[testParameters.length * 2][];
			String description;

			for(int i=0, resultIndex=0; i< testParameters.length; i++)
			{
				description = "static test key (p=" + TestKeysAndMP3Parameters.TEST_KEY_SIZES[i][0] +
				" q=" + TestKeysAndMP3Parameters.TEST_KEY_SIZES[i][1] + ") ";
				result[resultIndex++] = new Object[] {description + " same generator" , testParameters[i][0], testParameters[i][1], r};
				result[resultIndex++] = new Object[] {description + " new generator" , testParameters[i][0], testParameters[i][2], r};
			}

			return result;
		
		}catch(Exception e)
		{
			System.out.println("Problem in new parameters generation");
			e.printStackTrace();
			return null;
		}
	}
	
	
	@Test(dataProvider = "staticKeyProvider")
	public void staticCandidateVoteTest(String description, ElGamalKeyPair keyPair, MP3Parameters mp3Param, Random r) throws NoSuchAlgorithmException {
		//YESvote test
		candidateVoteTest(true, description, keyPair, mp3Param, r);
		//NOvote test
		candidateVoteTest(false, description, keyPair, mp3Param, r);
	}



	public void candidateVoteTest(boolean YESvote, String description, ElGamalKeyPair keyPair, MP3Parameters mp3Param, Random r) throws NoSuchAlgorithmException {
		System.out.println((YESvote ? "YESvote test : " : "NOvote test : ") + description);

		ElGamalPublicKey kpub = keyPair.publicKey;
		ElGamalPrivateKey kpri = keyPair.privateKey;

		/*** create prepared candidate vote encryption ***/
		MP3PreparedCandidateVote preparedCvote = CandidateVoteTestUtil.getMP3PreparedCandidateVote(
				YESvote, mp3Param, r, TEST_HASH_FUNCTION);

		/*** finish candidate vote creation with the selection of a random challenge ***/
		// step 1 - create random challenge
		BigInteger chal = CryptoUtil.generateRandomNumber(mp3Param.ELECTION_PUBLIC_KEY.q, r);
		// step 2 create final cvote 
		MP3CandidateVoteEncryption cvote = preparedCvote.getCandidateEncryption(chal, mp3Param.ELECTION_PUBLIC_KEY.q);

		/*** start test ***/
		// public test 
		CandidateVoteTestUtil.cvotePublicVerification(cvote, chal, mp3Param, kpub,TEST_HASH_FUNCTION);
		// private test
		CandidateVoteTestUtil.cvotePrivateVerification(YESvote, cvote, chal, mp3Param, kpri);		  
	}


	/**
	  @465Test(dataProvider = "AllDynamicMP3TestParametersProvider")
	  public void dynamicCandidateVoteTest(String description, ElGamalKeyPair keyPair, MP3Parameters mp3Param, Random r) throws NoSuchAlgorithmException {
		  //YESvote test
		  candidateVoteTest(true, description, keyPair, mp3Param, r);
		  //NOvote test
		  candidateVoteTest(false, description, keyPair, mp3Param, r);
	  }
	 **/

}
