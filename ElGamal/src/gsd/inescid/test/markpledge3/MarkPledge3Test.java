package gsd.inescid.test.markpledge3;

import gsd.inescid.crypto.*;
import gsd.inescid.crypto.util.Base64;
import gsd.inescid.crypto.util.CryptoUtil;
import gsd.inescid.markpledge3.*;
import gsd.inescid.test.crypto.ElGamalTest;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Scanner;

public class MarkPledge3Test {

	/**
	 * @param args
	 * @throws GeneralSecurityException 
	 */
	public static void main(String[] args) throws GeneralSecurityException {
		boolean useDefaultStaticElGamalKeyPair = false;
		boolean useDifferent2ndGenerator = false;
		
		int newModulusSize = 2048;
		int newQSize = 256;
		Random r = new SecureRandom();
		String hashAlgorithm = "SHA-1";
		
		
		// SET ELECTION KEY PAIR
		if( ! useDefaultStaticElGamalKeyPair)
			ElGamalTest.buildNewStaticKeyPair(newModulusSize,newQSize);
		
		ElGamalKeyPair kp = ElGamalTest.staticTestKeyPair; 
		System.out.println("Election KeyPair\n" + kp);
		
		//SET MarkPledge3 Parameters
		kp.publicKey.init(r);
		ElGamalKeyParameters keyParam = kp.getKeyParameters();
		
		BigInteger secondGenerator;
		if (!useDefaultStaticElGamalKeyPair && useDifferent2ndGenerator)
			secondGenerator = ElGamalTest.staticParameters.getQOrderGenerator(2);
		else
			secondGenerator = keyParam.g;
		
		MP3Parameters MP3Param = new MP3Parameters(kp.publicKey, secondGenerator);
		System.out.println(MP3Param);
	
		//tests
		testCandidateVote(kp, MP3Param, r, hashAlgorithm);
		//testVoteEncryption(MP3Param, hashAlgorithm, r, kp.privateKey);	
	}
	
	
	public static void testVoteEncryption(MP3Parameters MP3Param, String hashAlgorithm, Random r, ElGamalPrivateKey kpri) throws NoSuchAlgorithmException
	{
		Scanner input = new Scanner(System.in);
		int nCandidates, selection;
		BigInteger pledge, challenge;
		byte[] voteHash;
		MP3VoteAndReceipt vote;
		long begin, end;
		boolean verification;
		
		//get number of candidates
		System.out.print("\nInsert the number of candidates in the election: ");
		nCandidates = input.nextInt();
		
		MP3VoteFactory factory = new MP3VoteFactory(MP3Param, hashAlgorithm, r, true);
		begin = System.currentTimeMillis();
		factory.prepareVote(nCandidates);
		end = System.currentTimeMillis();
		voteHash = factory.getPreparedVoteHash();
		pledge = factory.getPledgeValue();
		
		System.out.println("Prepared vote ("+ (end-begin)+ "ms) hash: " + Base64.encode(voteHash));
		
		//pledge value to the voter and get the selected candidate index [0-nCandidates[ and challenge
		System.out.println("Pledge value: " + pledge);
		System.out.print("Enter your vote choice (A-" + (char)('A' + (nCandidates-1)) + "): ");
		selection = input.next().charAt(0) - 'A';
		
		System.out.print("Enter your vote challenge: ");
		challenge = new BigInteger(input.next());
		
		vote = factory.getVoteAndReset(challenge, selection);
		voteHash = vote.getHash(hashAlgorithm);
		System.out.println("Final vote hash: " + Base64.encode(voteHash));
		System.out.println("\n" + vote.getReceipt());
		
		begin = System.currentTimeMillis();
		verification = votePublicReceiptVerification(vote, MP3Param);
		end = System.currentTimeMillis();
		System.out.println("\nPublic vote verification passed ("+ (end-begin)+ "ms)? " + verification);
		
		begin = System.currentTimeMillis();
		verification = voteVerificationByDecryption(vote, MP3Param, kpri);
		end = System.currentTimeMillis();
		System.out.println("Vote verification by decryption passed ("+ (end-begin)+ "ms)? " + verification);
		
		int selectionIndex = (selection + vote.FIRST_CANDIDATE_INDEX) % nCandidates;
		BigInteger verificationPledge = vote.CANDIDATE_VOTES[selectionIndex].VERIFICATION_VALUE;
		System.out.println("Voter pledge verification passed?: " + verificationPledge.equals(pledge));
		
	}
	
	

	public static boolean votePublicReceiptVerification(MP3VoteAndReceipt vote, MP3Parameters param)
	{
		boolean verification = true;
		
		ElGamalVerifiableEncryption cvEnc;
		ElGamalPublicKey kpub = param.ELECTION_PUBLIC_KEY;
		BigInteger verificationMessage = param.BASE_VOTE_GENERATOR.modPow(vote.CHALLENGE, kpub.p);
		
		for(int i=0; i < vote.CANDIDATE_VOTES.length; i++)
		{
			//verify candidate vote
			cvEnc = getVerifiableEncryption(i, vote, kpub);
			verification = verification & kpub.verifyQOrderMessageEncryption(verificationMessage,cvEnc);
			
			//verify candidate vote with build in verifiable encryption construction 
			//cvEnc = vote.CANDIDATE_VOTES[i].getVerifiableEncryption(vote.CHALLENGE, kpub.p, kpub.q);
			//verification = verification & kpub.verifyQOrderMessageEncryption(verificationMessage,cvEnc);
		}
		return verification;
	}
	
	
	/**
	 * This method builds a verifiable ElGamal encryption for the selected 
	 * candidate vote encryption of the vote
	 * @param i index of the candidate vote encryption
	 * @param vote the vote
	 * @param kpub election public key
	 * @return the verifiable ElGamal encryption
	 */
	public static ElGamalVerifiableEncryption getVerifiableEncryption(int i, MP3VoteAndReceipt vote, ElGamalPublicKey kpub)
	{
		BigInteger cvX = vote.CANDIDATE_VOTES[i].BIT_ENCRYPTION.X;
		BigInteger cvY = vote.CANDIDATE_VOTES[i].BIT_ENCRYPTION.Y;
		BigInteger commitX = vote.CANDIDATE_VOTES[i].COMMIT_ENCRYPTION.X;
		BigInteger commitY = vote.CANDIDATE_VOTES[i].COMMIT_ENCRYPTION.Y;
		
		BigInteger distance = vote.CHALLENGE.subtract(vote.CANDIDATE_VOTES[i].VERIFICATION_VALUE).mod(kpub.q);

		BigInteger newX = (cvX.modPow(distance, kpub.p).multiply(commitX)).mod(kpub.p);
		BigInteger newY = (cvY.modPow(distance, kpub.p).multiply(commitY)).mod(kpub.p);
		
		return new ElGamalVerifiableEncryption(new ElGamalEncryption(newX, newY), vote.CANDIDATE_VOTES[i].VERIFICATION_ENCRYPTION_FACTOR);
	}
	
	
	
	public static boolean voteVerificationByDecryption(MP3VoteAndReceipt vote, MP3Parameters param, ElGamalPrivateKey kpri)
	{
		boolean verification = true;
		
		ElGamalVerifiableEncryption cvEnc;
		ElGamalPublicKey kpub = param.ELECTION_PUBLIC_KEY;
		BigInteger verificationMessage = param.BASE_VOTE_GENERATOR.modPow(vote.CHALLENGE, kpub.p);
		BigInteger decryptedMessage;
		
		for(int i=0; i < vote.CANDIDATE_VOTES.length; i++)
		{
			//verify candidate vote
			cvEnc = getVerifiableEncryption(i, vote, kpub);
			decryptedMessage = kpri.decryptQOrderMessage(cvEnc.MESSAGE_ENCRYPTION);
			verification = verification & decryptedMessage.equals(verificationMessage);
			
			//verify candidate vote with build in verifiable encryption construction 
			//cvEnc = vote.CANDIDATE_VOTES[i].getVerifiableEncryption(vote.CHALLENGE, kpub.p, kpub.q);
			//decryptedMessage = kpri.decryptQOrderMessage(cvEnc.MESSAGE_ENCRYPTION);
			//verification = verification & decryptedMessage.equals(verificationMessage);
			
		}
		return verification;
	}
	
	
	
	
	public static void testCandidateVote(ElGamalKeyPair kp, MP3Parameters MP3Param, Random r, String hashFunction) throws NoSuchAlgorithmException
	{
		
		BigInteger commit = CryptoUtil.generateRandomNumber(MP3Param.ELECTION_PUBLIC_KEY.q, r);
		BigInteger challenge = CryptoUtil.generateRandomNumber(MP3Param.ELECTION_PUBLIC_KEY.q, r);
		
		MP3PreparedCandidateVote mp3CandidateEnc;
		
		ElGamalVerifiableEncryption cvEnc;
		ElGamalVerifiableEncryption commiEnc  = MP3Param.ELECTION_PUBLIC_KEY.encryptVerifiableQOrderMessage(
				MP3Param.BASE_VOTE_GENERATOR.modPow(commit, MP3Param.ELECTION_PUBLIC_KEY.p));
		
		
		//Yes vote test*****************************************************************************
		System.out.println("\n\n********** YES-VOTE *********");
		cvEnc = MP3Param.ELECTION_PUBLIC_KEY.encryptVerifiableQOrderMessage(MP3Param.BASE_VOTE_GENERATOR);
		mp3CandidateEnc = new MP3PreparedCandidateVote(true, cvEnc,null, commiEnc, commit);
		verifyCandidateVoteEncryption(kp, MP3Param, commit, challenge,
				mp3CandidateEnc);
		
		//create cvote validity proof data
		CGS97BallotValidity validity1 = new CGS97BallotValidity(true, cvEnc, kp.publicKey, MP3Param.BASE_VOTE_GENERATOR, null, null);
		CGS97BallotValidity validity2 = new CGS97BallotValidity(true, cvEnc, kp.publicKey, MP3Param.BASE_VOTE_GENERATOR_INVERSE, null, null);
		CGS97BallotValidity validity3 = new CGS97BallotValidity(false, cvEnc, kp.publicKey, MP3Param.BASE_VOTE_GENERATOR, null, null);
		CGS97BallotValidity validity4 = new CGS97BallotValidity(false, cvEnc, kp.publicKey, MP3Param.BASE_VOTE_GENERATOR_INVERSE, null, null);
		
		//verify cvote validity proof data
		System.out.println("\n***** Validity Test *****");
		MessageDigest md = MessageDigest.getInstance(hashFunction);
		System.out.println("Verify Validity 1 expected true -> " + 
				CGS97BallotValidity.verifyBallotValidity(cvEnc.MESSAGE_ENCRYPTION, validity1, kp.publicKey, 
						MP3Param.BASE_VOTE_GENERATOR, MP3Param.BASE_VOTE_GENERATOR_INVERSE, md));
		System.out.println("Verify Validity 2 expected false -> " + 
				CGS97BallotValidity.verifyBallotValidity(cvEnc.MESSAGE_ENCRYPTION, validity2, kp.publicKey, 
						MP3Param.BASE_VOTE_GENERATOR, MP3Param.BASE_VOTE_GENERATOR_INVERSE, md));
		System.out.println("Verify Validity 3 expected false -> " + 
				CGS97BallotValidity.verifyBallotValidity(cvEnc.MESSAGE_ENCRYPTION, validity3, kp.publicKey, 
						MP3Param.BASE_VOTE_GENERATOR, MP3Param.BASE_VOTE_GENERATOR_INVERSE, md));
		System.out.println("Verify Validity 4 expected false -> " + 
				CGS97BallotValidity.verifyBallotValidity(cvEnc.MESSAGE_ENCRYPTION, validity4, kp.publicKey, 
						MP3Param.BASE_VOTE_GENERATOR, MP3Param.BASE_VOTE_GENERATOR_INVERSE, md));
		
		
		
		
		//No vote test*****************************************************************************
		System.out.println("\n\n********** NO-VOTE *********");
		cvEnc = MP3Param.ELECTION_PUBLIC_KEY.encryptVerifiableQOrderMessage(MP3Param.BASE_VOTE_GENERATOR_INVERSE);
		mp3CandidateEnc = new MP3PreparedCandidateVote(false, cvEnc,null, commiEnc, commit);
		verifyCandidateVoteEncryption(kp, MP3Param, commit, challenge,
				mp3CandidateEnc);
		
		
		//create cvote validity proof data
		validity1 = new CGS97BallotValidity(true, cvEnc, kp.publicKey, MP3Param.BASE_VOTE_GENERATOR, null, null);
		validity2 = new CGS97BallotValidity(true, cvEnc, kp.publicKey, MP3Param.BASE_VOTE_GENERATOR_INVERSE, null, null);
		validity3 = new CGS97BallotValidity(false, cvEnc, kp.publicKey, MP3Param.BASE_VOTE_GENERATOR, null, null);
		validity4 = new CGS97BallotValidity(false, cvEnc, kp.publicKey, MP3Param.BASE_VOTE_GENERATOR_INVERSE, null, null);
		
		//verify cvote validity proof data
		System.out.println("\n***** Validity Test *****");
		System.out.println("Verify Validity 1 expected false -> " + 
				CGS97BallotValidity.verifyBallotValidity(cvEnc.MESSAGE_ENCRYPTION, validity1, kp.publicKey, 
						MP3Param.BASE_VOTE_GENERATOR, MP3Param.BASE_VOTE_GENERATOR_INVERSE, md));
		System.out.println("Verify Validity 2 expected false -> " + 
				CGS97BallotValidity.verifyBallotValidity(cvEnc.MESSAGE_ENCRYPTION, validity2, kp.publicKey, 
						MP3Param.BASE_VOTE_GENERATOR, MP3Param.BASE_VOTE_GENERATOR_INVERSE, md));
		System.out.println("Verify Validity 3 expected false -> " + 
				CGS97BallotValidity.verifyBallotValidity(cvEnc.MESSAGE_ENCRYPTION, validity3, kp.publicKey, 
						MP3Param.BASE_VOTE_GENERATOR, MP3Param.BASE_VOTE_GENERATOR_INVERSE, md));
		System.out.println("Verify Validity 4 expected true -> " + 
				CGS97BallotValidity.verifyBallotValidity(cvEnc.MESSAGE_ENCRYPTION, validity4, kp.publicKey, 
						MP3Param.BASE_VOTE_GENERATOR, MP3Param.BASE_VOTE_GENERATOR_INVERSE, md));
		
		
		
		
	}


	private static void verifyCandidateVoteEncryption(ElGamalKeyPair kp,
			MP3Parameters MP3Param, BigInteger commit,
			BigInteger challenge,
			MP3PreparedCandidateVote mp3CandidateEnc) {
		MP3CandidateVoteEncryption candidateEncryption;
		ElGamalVerifiableEncryption challengeEncryption;
		BigInteger verificationMessage;
		BigInteger decryptedCandidateVote;
		BigInteger decryptedCommit;
				
		candidateEncryption = mp3CandidateEnc.getCandidateEncryption(challenge, kp.publicKey.q);
			
		System.out.println(mp3CandidateEnc);
		System.out.println("\nFinal VOTE" + candidateEncryption);
		
		challengeEncryption = candidateEncryption.getVerifiableEncryption(challenge, kp.publicKey.p, kp.publicKey.q);
		verificationMessage = MP3Param.BASE_VOTE_GENERATOR.modPow(challenge, kp.publicKey.p);
		
		System.out.println("\n***** Encryption verification test *****");
		System.out.println("G^1  = " + MP3Param.BASE_VOTE_GENERATOR);
		System.out.println("G^-1 = " + MP3Param.BASE_VOTE_GENERATOR_INVERSE);
		System.out.println("Challenge = " + challenge);
		System.out.println("G^Challenge = " + verificationMessage);
		
		System.out.println("Verifiable encryption verification test: " 
				+ kp.publicKey.verifyQOrderMessageEncryption(verificationMessage,challengeEncryption));
		
		
		System.out.println("\n***** Decryption tests *****");
		decryptedCandidateVote = kp.privateKey.decryptQOrderMessage(candidateEncryption.BIT_ENCRYPTION);
		System.out.println("Decrypted candidate vote = " + decryptedCandidateVote +
						   " (" + ((decryptedCandidateVote.compareTo(MP3Param.BASE_VOTE_GENERATOR)==0)? "YES":"NO") + "-vote)");
		
		decryptedCommit = kp.privateKey.decryptQOrderMessage(candidateEncryption.COMMIT_ENCRYPTION);
		System.out.println("Decrypted commit value = " + decryptedCommit);
		System.out.println("Initial commit = " + commit);
		System.out.println("G^commit = " + MP3Param.BASE_VOTE_GENERATOR.modPow(commit, kp.publicKey.p));
		
		System.out.println("Decrypted challenge encryption: " + kp.privateKey.decryptQOrderMessage(challengeEncryption.MESSAGE_ENCRYPTION));
		System.out.println("G^Challenge mod p: " + verificationMessage);
	}
	

}
