package gsd.inescid.markpledge.mp1a;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.crypto.ElGamalPublicKey;
import gsd.inescid.crypto.ElGamalVerifiableEncryption;
import gsd.inescid.markpledge.MPEncryptedVote;
import gsd.inescid.markpledge.MPReceipt;
import gsd.inescid.markpledge.MPValidityProof;
import gsd.inescid.markpledge.MarkPledgeType;
import gsd.inescid.markpledge.interfaces.IMPEncryptedVote;
import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.interfaces.IMPReceipt;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;
import gsd.inescid.markpledge.mp1.MP1VoteReceiptFactory;
import gsd.inescid.markpledge.smartclient.CardUtil;
import gsd.inescid.markpledge3.CGS97BallotValidity;

public class MP1AVoteReceiptFactory extends MP1VoteReceiptFactory {

	protected BigInteger[] canonicalEncryptionFactors;
	protected ElGamalEncryption[] canonicalEncrytions;
	
	public MP1AVoteReceiptFactory(IMPParameters param, Random randomSource) {
		super(param, randomSource);
		this.type = MarkPledgeType.MP1A;
	}
	
	protected void createRandomInitializationData()
	{
		super.createRandomInitializationData();
		
		//create canonical vote encryption factors
		this.canonicalEncryptionFactors = new BigInteger[this.numberOfCandidates];
		for(int i=0; i<this.numberOfCandidates; i++)
			this.canonicalEncryptionFactors[i] = 
					(new BigInteger(this.param.getQLengthInBytes() * 8, this.randomSource)).mod(this.param.getQ());		
	}
	
	public IMPEncryptedVote getEncryptedVote() 
	{
		super.getEncryptedVote();
		MPEncryptedVote encVote = new MPEncryptedVote(this.numberOfCandidates);
		
		ElGamalEncryption[] candidateEncryption;
		
		ElGamalPublicKey kpub = this.param.getPublicKey();
		BigInteger one = this.param.getMP_G();
		BigInteger zero = this.param.getMP_GInv();
		int alpha = this.param.getAlpha();
		
		this.canonicalEncrytions = new ElGamalEncryption[this.numberOfCandidates];
		for(int i=0; i<this.numberOfCandidates; i++)
		{
			if(i==this.yesVotePosition)
			{
				this.canonicalEncrytions[i] = kpub.encryptQOrderMessage(one, this.canonicalEncryptionFactors[i]);
			} else {
				this.canonicalEncrytions[i] = kpub.encryptQOrderMessage(zero, this.canonicalEncryptionFactors[i]);
			}
			
			candidateEncryption = new ElGamalEncryption[alpha*2+1];
			System.arraycopy(this.voteEnc.getCandidateEncryption(i), 0, candidateEncryption, 1, alpha*2);
			candidateEncryption[0] = this.canonicalEncrytions[i];
			
			encVote.setCandidateVote(i, candidateEncryption);
		}
		
		//TODO
		//setVoteHash();
		
		return encVote;
	}
	
	public IMPReceipt getReceipt(int selectedCandidateIndex,
			BigInteger challenge) 
	{
		super.getReceipt(selectedCandidateIndex, challenge);
		
		int alpha = this.param.getAlpha();
		BigInteger q = this.param.getQ();
		
		MPReceipt receipt = new MPReceipt(this.numberOfCandidates);
		receipt.setChallenge(challenge);
		receipt.setRotation(this.receipt.getRotation());
		
		
		
		BigInteger[][] validityFactors = this.receipt.getReceiptValidity();
		BigInteger[] vcodes = this.receipt.getVerificationCodes();
		BigInteger conformityFactor;
		BigInteger canonicalFactor, hiddenBMPFactor;
		
		for(int i=0; i<this.numberOfCandidates; i++)
		{
			receipt.setVerificationCode(vcodes[i], i);
			canonicalFactor = this.canonicalEncryptionFactors[i];
			BigInteger[] finalVerificationFactors = new BigInteger[2*alpha];
			
			for(int a=alpha-1, iBMP=0; a>=0; a--, iBMP++)
			{
				if(challenge.testBit(a)) //hidden elelemt is left BMP element
					hiddenBMPFactor = this.BMPencryptionFactors[i][iBMP*2];
				else
					hiddenBMPFactor = this.BMPencryptionFactors[i][iBMP*2+1];
				
				//Conformity Factor
				if(vcodes[i].testBit(a)){ //bit b=1 revealed (subtract factors)
					conformityFactor = canonicalFactor.subtract(hiddenBMPFactor).mod(q);					
				} else { // bit b=0 revealed (add factors)
					conformityFactor = canonicalFactor.add(hiddenBMPFactor).mod(q);					
				}
				finalVerificationFactors[iBMP] = conformityFactor;
			}
			System.arraycopy(validityFactors[i], 0, finalVerificationFactors, alpha, alpha);
			receipt.setValidity(finalVerificationFactors, i);
		}
		
		return receipt;
	}
	
	public IMPValidityProof getValidityProof() {
		try{
			
		this.validity = new MPValidityProof(this.numberOfCandidates);
		
		BigInteger sumFactor = BigInteger.ZERO;
		CGS97BallotValidity proof;
		boolean yesVote;
		ElGamalVerifiableEncryption vEnc;
		ElGamalPublicKey kpub = this.param.getPublicKey();
		BigInteger m;
		BigInteger mpG = this.param.getMP_G();
		BigInteger mpGInv = this.param.getMP_GInv();
		String hashFunction = "SHA-1";
		
		for(int i=0; i<this.numberOfCandidates; i++)
		{
			if( i== this.yesVotePosition)
			{
				yesVote = true;
				m = mpG;
			}
			else
			{
				yesVote = false;
				m = mpGInv;
			}
			vEnc = new ElGamalVerifiableEncryption(this.canonicalEncrytions[i],
												   this.canonicalEncryptionFactors[i]);
			
			
			proof = new CGS97BallotValidity(yesVote, vEnc, kpub, m, this.randomSource, hashFunction);
			this.validity.setCanonicalVoteProof(proof, i);
			
			sumFactor = sumFactor.add(this.canonicalEncryptionFactors[i]);
		}
		
		this.validity.setVoteSumProof(sumFactor.mod(this.param.getQ()));
		
		return this.validity;
		
		}catch(Exception e)
		{
			e.printStackTrace();
			System.exit(-1);
		}
		return null;
	
	}
	
}
