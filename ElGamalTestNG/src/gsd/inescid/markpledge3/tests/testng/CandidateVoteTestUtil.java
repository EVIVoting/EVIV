package gsd.inescid.markpledge3.tests.testng;

import gsd.inescid.crypto.ElGamalPrivateKey;
import gsd.inescid.crypto.ElGamalPublicKey;
import gsd.inescid.crypto.ElGamalVerifiableEncryption;
import gsd.inescid.crypto.util.CryptoUtil;
import gsd.inescid.markpledge3.CGS97BallotValidity;
import gsd.inescid.markpledge3.MP3CandidateVoteEncryption;
import gsd.inescid.markpledge3.MP3Parameters;
import gsd.inescid.markpledge3.MP3PreparedCandidateVote;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class CandidateVoteTestUtil {
	
	
	/**
	 * Create a MP3PreparedCandidateVote of the specified type
	 * @param YESvote type of the candidate vote true->YESvote, false->NOvote
	 * @param mp3Param MP3 parameters
	 * @param r randomness source
	 * @param hashFunction hash function to use
	 * @return the candidate vote encryption
	 * @throws NoSuchAlgorithmException
	 */
	public static MP3PreparedCandidateVote getMP3PreparedCandidateVote(
			boolean YESvote, MP3Parameters mp3Param, Random r, String hashFunction)
	throws NoSuchAlgorithmException {

		// step 1 - define the value to encrypt in be accordingly to the type of cvote desired
		BigInteger beValue = YESvote ? mp3Param.BASE_VOTE_GENERATOR : mp3Param.BASE_VOTE_GENERATOR_INVERSE;

		// step 2 - encrypt be
		ElGamalVerifiableEncryption be = mp3Param.ELECTION_PUBLIC_KEY.encryptVerifiableQOrderMessage(beValue);

		// step 3 - create be validity proof data
		CGS97BallotValidity validity = new CGS97BallotValidity(YESvote, be, mp3Param.ELECTION_PUBLIC_KEY, beValue, r, hashFunction);

		// step 4 - choose random commit code and encrypt it 
		BigInteger ccodeValue = CryptoUtil.generateRandomNumber(mp3Param.ELECTION_PUBLIC_KEY.q, r);
		ElGamalVerifiableEncryption ccode  = mp3Param.ELECTION_PUBLIC_KEY.encryptVerifiableQOrderMessage(
				mp3Param.BASE_VOTE_GENERATOR.modPow(ccodeValue, mp3Param.ELECTION_PUBLIC_KEY.p));

		// step 5 - aggregate the previous steps output in a MP3PreparedCandidateVote,
		//		    it corresponds to a "prepared" cvote and corresponding validity proof 
		MP3PreparedCandidateVote preparedCvote= new MP3PreparedCandidateVote(YESvote, be, validity, ccode, ccodeValue);

		return preparedCvote;
	}

	/**
	 * Public verification of the correctness of the candidate vote construction
	 * @param cvote candidate vote to test
	 * @param chal challenge used in the cvote construction
	 * @param mp3Param MP3 parameters
	 * @param kpub public key
	 * @throws NoSuchAlgorithmException 
	 */
	public static boolean cvotePublicVerification(MP3CandidateVoteEncryption cvote,
			BigInteger chal, MP3Parameters mp3Param, ElGamalPublicKey kpub, String hashFunction) throws NoSuchAlgorithmException {

		boolean verification = true;

		// step 1 - verify be validity
		verification = verification && (CGS97BallotValidity.verifyBallotValidity(cvote.BIT_ENCRYPTION,
				cvote.BIT_ENCRYPTION_VALIDITY, 
				kpub, 
				mp3Param.BASE_VOTE_GENERATOR, 
				mp3Param.BASE_VOTE_GENERATOR_INVERSE, 
				MessageDigest.getInstance(hashFunction)) == true); 
		assert  verification : "vote validity check";

		// step 2 verification of the cvote 
		// step 2.1 - get validation data
		ElGamalVerifiableEncryption chalEncryption = cvote.getVerifiableEncryption(chal, kpub.p, kpub.q);
		// step 2.2 - create the message in the q-order subgroup of Z*_p that corresponds to the exponential chal encryption 
		BigInteger verificationMessage = mp3Param.BASE_VOTE_GENERATOR.modPow(chal, kpub.p);
		// step 2.3 - verify the chal encryption
		verification = verification && kpub.verifyQOrderMessageEncryption(verificationMessage, chalEncryption);
		assert verification : "cvote (chal encryption) public verification";

		return verification;
	}

	/** 
	 * Private verification by decryption the cvote entries (only for testing purposes)
	 * 
	 * @param YESvote type of candidate vote
	 * @param cvote candidate vote to test
	 * @param chal challenge used in the cvote creation
	 * @param mp3Param MP3 parameters
	 * @param kpri private key
	 */
	public static boolean cvotePrivateVerification(boolean YESvote, MP3CandidateVoteEncryption cvote, BigInteger chal,
			MP3Parameters mp3Param, ElGamalPrivateKey kpri) {

		boolean verification = true;


		// step 1 - test decryption of be
		BigInteger beValue = kpri.decryptQOrderMessage(cvote.BIT_ENCRYPTION);
		verification = verification && beValue.equals((YESvote ? mp3Param.BASE_VOTE_GENERATOR : mp3Param.BASE_VOTE_GENERATOR_INVERSE ));
		assert verification : "test decryption of be";

		// step 2 - test decryption of chal
		BigInteger chalValue = kpri.decryptQOrderMessage(cvote.getVerifiableEncryption(chal, kpri.p, kpri.q).MESSAGE_ENCRYPTION);
		BigInteger verificationChalValue = mp3Param.BASE_VOTE_GENERATOR.modPow(chal, kpri.p);
		verification = verification && chalValue.equals(verificationChalValue);
		assert verification : "test decryption of chal";

		// step 3 - test decryption of ccode
		BigInteger verificationValue = kpri.decryptQOrderMessage(cvote.COMMIT_ENCRYPTION);
		BigInteger verifyAgainstValue = YESvote ? cvote.VERIFICATION_VALUE : 
			chal.multiply(new BigInteger("2")).subtract(cvote.VERIFICATION_VALUE).mod(kpri.q);
		verifyAgainstValue = mp3Param.BASE_VOTE_GENERATOR.modPow(verifyAgainstValue, kpri.p);

		verification = verification && verificationValue.equals(verifyAgainstValue); 
		assert verification : "test decryption of commit";

		return verification;
	}

}
