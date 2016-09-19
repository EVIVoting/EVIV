package gsd.inescid.markpledge.mp3;

import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.crypto.ElGamalPublicKey;
import gsd.inescid.crypto.ElGamalVerifiableEncryption;
import gsd.inescid.markpledge.CGS97BallotValidity;
import gsd.inescid.markpledge.MPAbstractVoteReceiptFactory;
import gsd.inescid.markpledge.MPEncryptedVote;
import gsd.inescid.markpledge.MPReceipt;
import gsd.inescid.markpledge.MPValidityProof;
import gsd.inescid.markpledge.MarkPledgeType;
import gsd.inescid.markpledge.interfaces.IMPEncryptedVote;
import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.interfaces.IMPReceipt;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;

import java.math.BigInteger;
import java.util.Random;

public class MP3VoteReceiptFactory extends MPAbstractVoteReceiptFactory {

	protected BigInteger[] encryptedCommit;
	protected BigInteger[][] encryptionFactors;
	
	public MP3VoteReceiptFactory(IMPParameters param, Random randomSource) {
		super(MarkPledgeType.MP3, param, randomSource);
		//this.param = param;
	}
	
	
	@Override
	public void init(int numberOfCandidates) {
		super.init(numberOfCandidates);
		createRandomInitializationData();
	}
	
	protected void createRandomInitializationData()
	{
		BigInteger q = this.param.getQ();
		int qBits = this.param.getQLengthInBytes() * 8; 
		
		this.encryptedCommit = new BigInteger[this.numberOfCandidates];
		for(int i=0; i<this.numberOfCandidates; i++)
			this.encryptedCommit[i] = 
				(new BigInteger(qBits, this.randomSource)).mod(q);
		
		this.encryptionFactors = new BigInteger[this.numberOfCandidates][2];
		for(int i=0; i<this.numberOfCandidates; i++)
			for(int k=0; k<this.encryptionFactors[i].length; k++)
				this.encryptionFactors[i][k] = 
					(new BigInteger(qBits, this.randomSource)).mod(q);
		
	}
	

	public BigInteger getPledge() {
		return this.encryptedCommit[this.yesVotePosition];
	}
	
	public IMPEncryptedVote getEncryptedVote() {
		this.voteEnc = new MPEncryptedVote(this.numberOfCandidates);
		ElGamalPublicKey kpub = this.param.getPublicKey();
		ElGamalEncryption[] candidateEncryption;
		BigInteger m;
		BigInteger mpG = this.param.getMP_G();
		BigInteger mpGInv = this.param.getMP_GInv();
			
		for(int i=0; i<this.numberOfCandidates; i++)
		{
			candidateEncryption = new ElGamalEncryption[2];
		
			if(i==this.yesVotePosition) //encrypt YESvote
				candidateEncryption[0] = kpub.encryptQOrderMessage(mpG,
						this.encryptionFactors[i][0]);
			else // encrypt NOvote
				candidateEncryption[0] = kpub.encryptQOrderMessage(mpGInv,
						this.encryptionFactors[i][0]);
			
			m = mpG.modPow(this.encryptedCommit[i], kpub.p);
			candidateEncryption[1] = kpub.encryptQOrderMessage(m,
					this.encryptionFactors[i][1]);
								
			this.voteEnc.setCandidateVote(i, candidateEncryption);
		}
		
		setVoteHash();
		
		return this.voteEnc;
	}
		
	public IMPReceipt getReceipt(int selectedCandidateIndex,
			BigInteger challenge) {
		
		this.receipt = new MPReceipt(this.numberOfCandidates);
		this.receipt.setChallenge(challenge);	
		this.receipt.setRotation(getVoteRotation(selectedCandidateIndex));

		BigInteger q=this.param.getQ();
		BigInteger aux;
		BigInteger two = new BigInteger("2");
		
		for(int i=0; i<this.numberOfCandidates; i++)
		{
			if(i == this.yesVotePosition)
			{
				aux = this.encryptedCommit[i];
			}
			else
			{
				aux = two.multiply(challenge).subtract(
						this.encryptedCommit[i]).mod(q);
				
				this.encryptedCommit[i] = aux;
			}
			this.receipt.setVerificationCode(aux, i);			
			aux = challenge.subtract(aux).multiply(this.encryptionFactors[i][0]).add(
					this.encryptionFactors[i][1]).mod(q);
			
			this.receipt.setValidity(new BigInteger[]{aux}, i);
		}
		return this.receipt;
	}

	public IMPValidityProof getValidityProof() {
		try{
			this.validity = new MPValidityProof(this.numberOfCandidates);
			
			ElGamalEncryption[][] voteEnc = this.voteEnc.getEncryptedVote();	
			
			BigInteger q=this.param.getQ();
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
					
				vEnc = new ElGamalVerifiableEncryption(voteEnc[i][0], this.encryptionFactors[i][0]);
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
				proof = new CGS97BallotValidity(yesVote, vEnc, kpub, m, this.randomSource, hashFunction);
				this.validity.setCanonicalVoteProof(proof, i);
				
				sumFactor = sumFactor.add(this.encryptionFactors[i][0]);
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
