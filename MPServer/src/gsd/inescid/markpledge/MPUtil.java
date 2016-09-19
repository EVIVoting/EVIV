package gsd.inescid.markpledge;

import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.crypto.ElGamalKeyFactory;
import gsd.inescid.crypto.ElGamalKeyPair;
import gsd.inescid.crypto.ElGamalKeyParameters;
import gsd.inescid.crypto.ElGamalPrivateKey;
import gsd.inescid.crypto.ElGamalPublicKey;
import gsd.inescid.crypto.ElGamalVerifiableEncryption;
import gsd.inescid.crypto.MP2ElGamalKeyParameters;
import gsd.inescid.crypto.util.Base64;
import gsd.inescid.crypto.util.CryptoUtil;
import gsd.inescid.markpledge.interfaces.IMPEncryptedVote;
import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.interfaces.IMPReceipt;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;
import gsd.inescid.markpledge.interfaces.IMPVoteAndReceipt;
import gsd.inescid.markpledge.mp1.MP1VoteAndReceipt;
import gsd.inescid.markpledge.mp1a.MP1AVoteAndReceipt;
import gsd.inescid.markpledge.mp2.MP2Parameters;
import gsd.inescid.markpledge.mp2.MP2VoteAndReceipt;
import gsd.inescid.markpledge.mp2.interfaces.IMP2Parameters;
import gsd.inescid.markpledge.mp3.MP3VoteAndReceipt;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class MPUtil {
	public static final String DEFAULT_HASH_FUNCTION = "SHA-1";
	
	/**
	 * Method to obtain the hash value of the a vote encryption.
	 * 
	 * @param vote the encrypted vote.
	 * @param hashFunction name of the hash function to use. 
	 * 						If null the DEFAULT_HASH_FUNCTION is used.
	 * @param modulusByteLength the key pair p parameter length (encryption modulus).
	 * @return the hash code of all the ElGamal encryptions of the encrypted vote.
	 * @throws NoSuchAlgorithmException if there is no provider offering the specified hash function.    
	 */
	public static byte[] computeVoteEncryptionHashCode(IMPEncryptedVote vote, String hashFunction, int modulusByteLength) throws NoSuchAlgorithmException {
		if(hashFunction == null)
			hashFunction = MPUtil.DEFAULT_HASH_FUNCTION;
		
		ElGamalEncryption[][] encryptedVote = vote.getEncryptedVote();
		MessageDigest digest = MessageDigest.getInstance(hashFunction);
		digest.reset();
		
		for(int i=0; i<encryptedVote.length; i++)
			for(int k=0; k<encryptedVote[i].length; k++)
			{
				digest.update(CryptoUtil.copyLastBytesOf(encryptedVote[i][k].X.toByteArray(), modulusByteLength));
				digest.update(CryptoUtil.copyLastBytesOf(encryptedVote[i][k].Y.toByteArray(), modulusByteLength));
			}
		return digest.digest();
	}
	
	
	/**
	 * Method to obtain the hash value of the vote encryption. It uses the hash chaining technique
	 * to solve allow an alternative verification of vote encryption performed on resource 
	 * constrained devices, e.g. smart cards. 
	 * 
	 * @param vote the encrypted vote.
	 * @param hashFunction name of the hash function to use. 
	 * 						If null the DEFAULT_HASH_FUNCTION is used.
	 * @param modulusByteLength the key pair p parameter length (encryption modulus).
	 * @return the hash code of all the ElGamal encryptions of the encrypted vote. The hash code 
	 * 			is computed using the hash chaining technique, i.e. 
	 * 			hash_n(cv_n || hash_n-1), where hash_0 = hash(cv_0). 
	 * 			cv_0 represents the first candidate encryption encryption and cv_n the n th candidate encryption.
	 * 			The returned result is hash_n where n = number of candidates - 1. 
	 * @throws NoSuchAlgorithmException if there is no provider offering the specified hash function.   
	 */
	public static byte[] computeVoteEncryptionHashChainingCode(IMPEncryptedVote vote, String hashFunction, int modulusByteLength) throws NoSuchAlgorithmException {
		if(hashFunction == null)
			hashFunction = MPUtil.DEFAULT_HASH_FUNCTION;
		
		ElGamalEncryption[][] encryptedVote = vote.getEncryptedVote();
		MessageDigest digest = MessageDigest.getInstance(hashFunction);
		byte[] aux = new byte[0];
		byte[][] encryptionBytes;
				
		digest.reset();
		for(int i=0; i<encryptedVote.length; i++)
		{
			for(int k=0; k<encryptedVote[i].length; k++)
			{
				encryptionBytes = encryptedVote[i][k].toByteArray(modulusByteLength);
				digest.update(encryptionBytes[0]);
				digest.update(encryptionBytes[1]);
			}
			digest.update(aux);
			aux = digest.digest();
		}
		return aux;
	}
	
	
	/**
	 * Computes the vote/receipt hash. 
	 * 
	 * IMPORTANT NOTE: all verification codes, receipt validity values and challenge are converted
	 * 				   to a byte array with length equal to verificationFactorsByteLength.
	 * 
	 * @param receipt the receipt
	 * @param hashFunction name of the hash function to use. 
	 * 						If null the DEFAULT_HASH_FUNCTION is used.
	 * @param verificationFactorsByteLength the verification factors length (both the verification codes and the vote validity values. It also defines the challenge length).
	 * @return receipt hash = H(H(voteHash)||H(verification codes)||H(receipt validity)||challenge||rotation) - the rotation is assumed to be one byte.
	 * @throws NoSuchAlgorithmException if there is no provider offering the specified hash function.    
	 */
	public static byte[] computeVoteReceiptHashCode(IMPReceipt receipt, String hashFunction, int verificationFactorsByteLength) throws NoSuchAlgorithmException {
		if(hashFunction == null)
			hashFunction = MPUtil.DEFAULT_HASH_FUNCTION;
		
		
		BigInteger[] verificationCodes = receipt.getVerificationCodes();
		BigInteger[][] receiptValidity = receipt.getReceiptValidity();
		
		MessageDigest digest = MessageDigest.getInstance(hashFunction);
		byte[] vcodesH, rValidityH, chal;
		byte rotation;
		digest.reset();
		// verification codes
		for(int i=0; i<verificationCodes.length; i++)
			digest.update(CryptoUtil.copyLastBytesOf(verificationCodes[i].toByteArray(), verificationFactorsByteLength));
		vcodesH = digest.digest();
		// receipt validity
		for(int i=0; i<receiptValidity.length; i++)
			for(int k=0; k< receiptValidity[i].length; k++)
			digest.update(CryptoUtil.copyLastBytesOf(receiptValidity[i][k].toByteArray(), verificationFactorsByteLength));
		rValidityH = digest.digest();
		// challenge
		chal = CryptoUtil.copyLastBytesOf(receipt.getChallenge().toByteArray(), verificationFactorsByteLength);
		//rotation
		rotation = (byte)receipt.getRotation();
		
		//vote and receipt hash
		digest.update(receipt.getVoteHashCode());
		digest.update(vcodesH);
		digest.update(rValidityH);
		digest.update(chal);
		digest.update(rotation);
		return digest.digest();
	}
	
	
	/**
	 * Decrypts a canonical vote using an abstract candidates list (A, B, C,...).
	 *  
	 * @param canonicalVote canonical vote to decrypt.
	 * @param kpri private key to decrypt the vote encryption.
	 * @param param the MarkPledge parameters used in the vote encryption.
	 * @param type the MarkPledge ballot type
	 * @return a string representation of the canonical vote decryption . 
	 */
	public static String decryptedVote(ElGamalEncryption[] canonicalVote, ElGamalPrivateKey kpri, IMPParameters param, MarkPledgeType type)
	{
		String[] candidates = createAbstractCandidateList(canonicalVote.length);
		return decryptedVote(canonicalVote, kpri, candidates, param, type);
	}
	
	/**
	 * Decrypts a canonical vote.
	 *  
	 * @param canonicalVote canonical vote to decrypt
	 * @param kpri private key to decrypt the vote encryption
	 * @param candidateList the candidates list
	 * @param param the MarkPledge parameters used in the vote encryption.
	 * @param type the MarkPledge ballot type
	 * @return a string representation of the canonical vote decryption.
	 * @throws InvalidParameterException if the length of the candidateList does not match the 
	 * 			number of candidates in the receipt.
	 */
	public static String decryptedVote(ElGamalEncryption[] canonicalVote, ElGamalPrivateKey kpri, String[] candidateList, IMPParameters param, MarkPledgeType type){
		if (candidateList.length != canonicalVote.length)
			new InvalidParameterException("Invalid candidate list length");
		
		StringBuilder vote = new StringBuilder("Decrypted vote:\n");
		BigInteger decryption;
		BigInteger oneEncoding = param.getMP_G();
		BigInteger zeroEncoding;
//		if(type == MarkPledgeType.MP2)
//			zeroEncoding = BigInteger.ONE;
//		else
			zeroEncoding = param.getMP_GInv();
		
		
		vote.append("Candidate - Vote\n");
		for(int i=0; i<candidateList.length; i++)
		{	
			decryption = kpri.decryptQOrderMessage(canonicalVote[i]);
			vote.append(candidateList[i]);
			vote.append("\t - ");
			if(decryption.equals(oneEncoding))
				vote.append("1");
			else if (decryption.equals(zeroEncoding))
				vote.append("0");
			else
				vote.append("Decryption error:" + decryption);
			
			vote.append("\n");
		}
		return vote.toString();
	}
	
	/**
	 * Decrypts a canonical vote.
	 *  
	 * @param canonicalVote canonical vote to decrypt
	 * @param kpri private key to decrypt the vote encryption
	 * @param param the MarkPledge parameters used in the vote encryption.
	 * @return an int[] containing the canonical vote decryption.
	 */
	public static int[] decryptedCanonicalVote(ElGamalEncryption[] canonicalVote, ElGamalPrivateKey kpri,
			IMPParameters param, int rotation){
	
		BigInteger decryption;
		BigInteger oneEncoding = param.getMP_G();
		BigInteger zeroEncoding = param.getMP_GInv();
		
		int[] results = new int[canonicalVote.length];
		
		for(int i=0; i<canonicalVote.length; i++)
		{	
			decryption = kpri.decryptQOrderMessage(canonicalVote[i]);
			if(decryption.equals(oneEncoding))
				results[i] = 1;
			else if (decryption.equals(zeroEncoding))
				results[i] = 0;
			else
				return null;
		}
		
		//perform rotation
		int[] aux = new int[results.length];
		
		for(int i=0, k=rotation; i<results.length; i++, k++)
		{
			k = k % results.length;
			aux[k] = results[i];
		}
		return aux;
	}
	

	/**
	 * Create a String representation of the receipt.
	 * @param receipt the receipt data (an IMPReceipt object).
	 * @param candidateList the list of the candidates names.
	 * @param vcodeRadix the base in which the verification codes should be displayed (it is used 
	 * 					 the conversion offered by the BigInteger class).
	 * @param alpha the bit size to truncate the receipt verification codes.
	 * @return a string representation of the receipt. The hash values and signature are presented 
	 * 		   in based 64 and the verification codes in base "vcodeRadix".
	 * @throws InvalidParameterException if the length of the candidateList does not match the 
	 * 			number of candidates in the receipt.  
	 */
	public static String getVoteReceiptText(IMPReceipt receipt, String[] candidateList, int vcodeRadix, int alpha)
	{
		BigInteger[] verificationCodes = receipt.getVerificationCodes();
		if (candidateList.length != verificationCodes.length)
			new InvalidParameterException("Invalid candidate list length");
		
		int verificationCodeIndex;
		int rotation = 0;//receipt.getRotation(); 
		byte[] vcode;
		
		StringBuilder r = new StringBuilder("Receipt for vote: " + Base64.encode(receipt.getVoteHashCode()) + "\n");
		r.append("Candidate \t- Verification Code\n");
		for(int i=0; i<candidateList.length; i++)
		{	
			verificationCodeIndex = (rotation + i) % candidateList.length;
			vcode = verificationCodes[verificationCodeIndex].toByteArray();
			vcode = CryptoUtil.truncateToAlphaBits(vcode, alpha);
			r.append(candidateList[i] + (new BigInteger(1, vcode)).toString(vcodeRadix).toUpperCase() + "\n");
		}
		
		//r.append("\nReceipt hash: " + Base64.encode(receipt.getHash()));
		//r.append("\nReceipt signature: " + Base64.encode(receipt.getSignature()));
		return r.toString();
	}
	
	
	/**
	 * Creates a string representation of the receipt using an abstract candidate list, i.e. A, B, C, D,...
	 * The verification codes in base 36 (converted by the BigInteger class) in its full size 
	 * (Q_LENGTH in MP3 and ALPHA_LENGTH in MP1 and MP2). The hash codes and signature are presented in base 64.
	 * 
	 * @param receipt the receipt data (an IMPReceipt object).
	 * @return the string representation of the receipt.
	 */
	public static String getVoteReceiptText(IMPReceipt receipt) {
	
		String[] candidates = createAbstractCandidateList(receipt.getVerificationCodes().length); 
		//TODO change to base 36
		return getVoteReceiptText(receipt, candidates, 16, -1);
	}
	
	
	 
	/**
	 * Creates an abstract candidate list, i.e. A, B, C, D,... 	
	 * @param nCandidates number of candidates
	 * @return an array of Strings with the abstract candidate names (A, B, C,...)
	 */
	public static String[] createAbstractCandidateList(int nCandidates)
	{
		String[] candidates = new String[nCandidates];
		for(int i=0; i<candidates.length; i++)
		{
			candidates[i] = Character.toString((char)('A' + i));
		}
		return candidates;
	}
	
	
	/**
	 * Verify the homomorphic canonical vote sum
	 * @param canonicalVotes
	 * @param verificationFactor the encryption factor that results from homomorphic addition of the canonical votes
	 * @param yesVoteEncoding the Z*p q order subgroup element that represents a yes vote
	 * @param noVoteEncoding the Z*p q order subgroup element that represents a no vote
	 * @param numberOfSelectedCandidates number of selected candidates in the vote
	 * @param kpub the public key used in the vote encryption
	 * @return true if the homomorphic sum corresponds to numberOfSelectedCandidates (yesVoteEncoding)  + canonicalVotes.length -
	 * 				numberOfSelectedCandidates * (noVoteEncoding)
	 */
	public static boolean verifyVoteSum(ElGamalEncryption[] canonicalVotes, BigInteger verificationFactor, 
										BigInteger yesVoteEncoding,	BigInteger noVoteEncoding, int numberOfSelectedCandidates, 
										ElGamalPublicKey kpub)
	{
		//Compute homomorphic encryption sum
		ElGamalEncryption homomorphicSum = canonicalVotes[0];
		for(int i=1; i<canonicalVotes.length; i++)
		{
			homomorphicSum = homomorphicSum.multiply(canonicalVotes[i], kpub.p);
		}
		
		//compute expected result
		int numberOfNoVotes = canonicalVotes.length - numberOfSelectedCandidates;
		BigInteger yesVotes = yesVoteEncoding.modPow(new BigInteger(Integer.toString(numberOfSelectedCandidates)),kpub.p);
		BigInteger noVotes = noVoteEncoding.modPow(new BigInteger(Integer.toString(numberOfNoVotes)), kpub.p);
		BigInteger total = (yesVotes.multiply(noVotes)).mod(kpub.p);
		
		//verify result
		ElGamalVerifiableEncryption toVerify = new ElGamalVerifiableEncryption(homomorphicSum, verificationFactor);
		return kpub.verifyQOrderMessageEncryption(total, toVerify);
	}
	
	/**
	 * Verify a canonical vote using the CGS97 validity proof
	 * @param canonicalVote 
	 * @param proofs CGS97 proofs
	 * @param yesVoteEncoding yes vote encoding used in the vote encryption
	 * @param noVoteEncoding no vote encoding used in the vote encryption
	 * @param kpub public key used in the vote encryption 
	 * @param md MessageDigest object to compute the CGS97 challenge 
	 * @return true if all proofs are valid and false otherwise.
	 */
	public static boolean verifyCanonicalVote(ElGamalEncryption[] canonicalVote, CGS97BallotValidity[] proofs, 
			BigInteger yesVoteEncoding,	BigInteger noVoteEncoding, ElGamalPublicKey kpub, MessageDigest md)
	{
		if (canonicalVote.length != proofs.length)
			new InvalidParameterException("Proofs length do not match the canonical vote encryption.");
		
		for(int i=0; i<canonicalVote.length; i++)
		{
			if(!CGS97BallotValidity.verifyBallotValidity(canonicalVote[i], proofs[i], kpub, yesVoteEncoding, noVoteEncoding, md))
			{
				System.out.println("CGS fail: " + i);
				return false;
			}
				
		}
		return true;
	}
	
	//create an MP2 key and mp2 parameters as they work for every MP type 
	public static MPKeyAndParameters generateKeyAndParameters(int pBitLength, int qBitLength, int alpha, MarkPledgeType mpType, boolean sameGenerator)
	{
		MP2ElGamalKeyParameters keyParam;
		ElGamalKeyPair kp; 
		
		keyParam = MP2ElGamalKeyParameters.getInstance(pBitLength,qBitLength,alpha);
		kp = ElGamalKeyFactory.createKeyPair(keyParam.getElGamalKeyParameters(), null); 
		MP2Parameters param = new MP2Parameters(keyParam, kp.publicKey, alpha);
		if(!sameGenerator)
		{
			int gIndex = keyParam.GENERATOR_INDEX + 1;
			try{
				BigInteger newGenerator = keyParam.getQOrderGenerator(gIndex);
				param.setMPExponentialMessageGenerator(newGenerator);
			} catch (GeneralSecurityException e)
			{
				System.out.println("Cannot create different generator. Using the key generator.");
			}
		}
		return new MPKeyAndParameters(param, kp);
	}
	
	
	//return static MP2 key and mp2 parameters as they work for every MP type 
	public static MPKeyAndParameters generateStaticKeyAndParameters(int pBitLength, int qBitLength, int alpha, MarkPledgeType mpType, boolean sameGenerator)
	{
		ElGamalKeyParameters keyParameters; 
		ElGamalKeyPair kp;
		ElGamalPublicKey kpub;
		ElGamalPrivateKey kpri;
		BigInteger SO2qOrder;
		BigInteger lambdaMultiplier;
		BigInteger lambda;
		BigInteger [][] SO2qGenerator;
		
		if(qBitLength==160)
		{
			// p=1024, q=160, lambda=24
			keyParameters = new ElGamalKeyParameters(
					new BigInteger("130669394292873982198830623179409066382959834531044804363355659421575838757245804076484660340730657014861518755485719199440354812436934032017998677737821462575631689120488450450515345486091163631878193710723678832579830427534841096535320430833706494346879579736733186483948519416972377097590679885603372168651"),
					new BigInteger("828821200974903434683609216032075036664291322501"),
					new BigInteger("94471534031346913216412333230293774519291435838505744317562665786909710134265005630371973035519284576906459764610719118163650605951001149350746626691733262065321281328209941255593218426505888613044315371474694694752291459751491748155368590417216985193717671491133502163959824308977162800100245187158776298292"));

			kpub = new ElGamalPublicKey(keyParameters,
					new BigInteger("110231638083927255693146979407934916351905416512465135145789198365148293833764465926115765730333614267605675510607412587618418328309352499281858172091086471472910626078832949213951415220025619743926743848918469877760475688875911951904534771304535115118253855319874019189735579352592321167229638330267378356166"));

			BigInteger kpriAux = new BigInteger("148344701575747897499706749691071086235706249224"); 
			kpri = new ElGamalPrivateKey(keyParameters, keyParameters.q.subtract(kpriAux));

			kp = new ElGamalKeyPair(kpub,kpri);

			SO2qGenerator = new BigInteger[][]{
					{new BigInteger("242433803834809773923124763936594205215494260492"),
						new BigInteger("633837593596553400270089699622089782140060763142")},
						{new BigInteger("194983607378350034413519516409985254524230559359"),
							new BigInteger("242433803834809773923124763936594205215494260492")}
			};

			SO2qOrder = new BigInteger("828821200974903434683609216032075036664291322500");
			lambdaMultiplier = new BigInteger("58160340404361453247391550618451824861316");
			lambda = new BigInteger("14250625");
		}
		else
		{
			// p=1024, q=512, lambda=24
			keyParameters = new ElGamalKeyParameters(
					new BigInteger("172672724268092827819306628805008773181459130100853266688753952995264878489413532509261506277787569961721601723114189790404967638370271513376944168983766466594523410542833959587246274787039822906701807231434702279619701653900261145318945033746139252696553384241928565057012019284838788804306638695236020988163"),
					new BigInteger("7708749558217848504717943317521254347220292579668997069817679640380067713715938003912054485107328250821606776207989180997912973079494497532321715407672337"),
					new BigInteger("159090185451517581725331572874309614366982478562325588372090231487495634433644903143724811294224931507150146168915681373150764368820226060147742205740348173645884884398999158103461902592825350188170095378561158065755881322025752343516148659416879861495317558685716093683814424886204673939011080719501840197998"));

			kpub = new ElGamalPublicKey(keyParameters,
					new BigInteger("120529085177337597850508615977662454645908822500743852953939673593936872511280876753406010169138448249304885251687769917279288372875929534509638444221551442543487699813488461107406015937806666206931062419559387936524729830864164140848231550626628625384913270994993078748264724075665998447921297221639442478444"));

			BigInteger kpriAux = new BigInteger("1724808370333293253224156859036948861123337507507881110356255021250101132432508965500487010917784461845242887215255049217612316912438176817363431567441897"); 
			kpri = new ElGamalPrivateKey(keyParameters, keyParameters.q.subtract(kpriAux));

			kp = new ElGamalKeyPair(kpub,kpri);

			SO2qGenerator = new BigInteger[][]{
						{new BigInteger("396284360865525344023128155511033214186706464008154251983584299657454005892798273881324693509133233467906034035798413325194034838491401586973990679139417"),
						 new BigInteger("5436584350980298805720325499187958603584751929624487223966681711801605226392819160569893905588990357683689259139104742363590053598985595095537729960349055")},
						{new BigInteger("2272165207237549698997617818333295743635540650044509845850997928578462487323118843342160579518337893137917517068884438634322919480508902436783985447323282"),
						 new BigInteger("396284360865525344023128155511033214186706464008154251983584299657454005892798273881324693509133233467906034035798413325194034838491401586973990679139417")}
			};

			SO2qOrder = new BigInteger("7708749558217848504717943317521254347220292579668997069817679640380067713715938003912054485107328250821606776207989180997912973079494497532321715407672336");
			lambdaMultiplier = new BigInteger("548200902368274151791225408384983824185732188770782358367185759909081152563239862641099612321923375879600302847138160431303763023269711626028627656");
			lambda = new BigInteger("14061906");
		}
				
		//TODO verify the key parameters
		MP2Parameters param = new MP2Parameters();
		param.setPublicKey(kpub);
		param.setAlpha(alpha);
		param.setLambda(lambda);
		param.setLambdaMultiplier(lambdaMultiplier);
		param.setMPExponentialMessageGenerator(kpub.g);
		param.setSO2qGenerator(SO2qGenerator);
		param.setSO2qOrder(SO2qOrder);
		
		
		return new MPKeyAndParameters(param, kp);
	}
	
	
	
	public static IMPVoteAndReceipt getVoteAndReceipt(MarkPledgeType ballotType, IMPEncryptedVote voteEnc,
			IMPReceipt receipt, IMPValidityProof validity)
	{
		switch(ballotType)
		{
			case MP1:
				return new MP1VoteAndReceipt(voteEnc, receipt, validity);
			case MP1A:
				return new MP1AVoteAndReceipt(voteEnc, receipt, validity);
			case MP2:
				return new MP2VoteAndReceipt(voteEnc, receipt, validity);
			case MP3:
				return new MP3VoteAndReceipt(voteEnc, receipt, validity);
			default:
				return null;
		}
	}
	
	public static BigInteger createChallenge(IMPParameters param, MarkPledgeType type)
	{
		BigInteger chal;
		switch(type)
		{
		case MP1:
		case MP1A:
			chal = new BigInteger(param.getAlphaByteLength() * 8, new Random());
			return chal;
			
		case MP2:
			chal = new BigInteger(param.getAlphaByteLength() * 8, new Random());
			chal = chal.mod(((IMP2Parameters)param).getLambda());
			return chal;
			
		case MP3:
			chal = new BigInteger(param.getQLengthInBytes() * 8, new Random());
			chal = chal.mod(param.getQ());
			return chal;
			
		default:
			return null;
		}
	}
}
