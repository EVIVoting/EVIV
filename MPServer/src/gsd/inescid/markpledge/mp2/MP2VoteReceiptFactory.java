package gsd.inescid.markpledge.mp2;

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
import gsd.inescid.markpledge.interfaces.IMPReceipt;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;

import java.math.BigInteger;
import java.util.Random;

public class MP2VoteReceiptFactory extends MPAbstractVoteReceiptFactory {

	protected BigInteger[] encryptedVectorIndex;
	protected BigInteger[][] encryptionFactors;
	protected MP2Parameters param;
	
	public MP2VoteReceiptFactory(MP2Parameters param, Random randomSource) {
		super(MarkPledgeType.MP2, null, randomSource);
		this.param = param;
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
		BigInteger lambda = this.param.getLambda();
		int lambdaBits = this.param.getAlphaByteLength() * 8;
		
		this.encryptedVectorIndex = new BigInteger[this.numberOfCandidates];
		for(int i=0; i<this.numberOfCandidates; i++)
			this.encryptedVectorIndex[i] = 
				(new BigInteger(lambdaBits, this.randomSource)).mod(lambda);
		
		this.encryptionFactors = new BigInteger[this.numberOfCandidates][2];
		for(int i=0; i<this.numberOfCandidates; i++)
			for(int k=0; k<this.encryptionFactors[i].length; k++)
				this.encryptionFactors[i][k] = 
					(new BigInteger(qBits, this.randomSource)).mod(q);
		
	}
	

	public BigInteger getPledge() {
		return this.encryptedVectorIndex[this.yesVotePosition];
	}
	
	public IMPEncryptedVote getEncryptedVote() {
		this.voteEnc = new MPEncryptedVote(this.numberOfCandidates);
		ElGamalPublicKey kpub = this.param.getPublicKey();
		ElGamalEncryption[] candidateEncryption;
		BigInteger[] vector;
		BigInteger m;
		BigInteger mpG = this.param.getMP_G();
		
		for(int i=0; i<this.numberOfCandidates; i++)
		{
			candidateEncryption = new ElGamalEncryption[2];
		
			if(i==this.yesVotePosition) //encrypt YESvote
				vector = this.param.getOneVector(this.encryptedVectorIndex[i]);
			else // encrypt NOvote
				vector = this.param.getZeroVector(this.encryptedVectorIndex[i]);
			
			m = mpG.modPow(vector[0], kpub.p);
			candidateEncryption[0] = kpub.encryptQOrderMessage(m,
					this.encryptionFactors[i][0]);
			
			m = mpG.modPow(vector[1], kpub.p);
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

		BigInteger oneVectorIndex;
		BigInteger[] chalVector;
		BigInteger lambda = this.param.getLambda();
		BigInteger q=this.param.getQ();
		
		chalVector = this.param.getTestVector(challenge);

		
		for(int i=0; i<this.numberOfCandidates; i++)
		{
			//compute verification factor
			/* dot product with chal vector */
			BigInteger aux1 = this.encryptionFactors[i][0].multiply(chalVector[0]).mod(q);
			BigInteger aux2 = this.encryptionFactors[i][1].multiply(chalVector[1]).mod(q);
			BigInteger vFactor = aux1.add(aux2).mod(q);
			this.receipt.setValidity(new BigInteger[]{vFactor}, i);
			
			if(i == this.yesVotePosition)
			{
				oneVectorIndex = this.encryptedVectorIndex[i];
			}
			else
			{
				oneVectorIndex = challenge.subtract(
						this.encryptedVectorIndex[i]).mod(lambda);
				
				this.encryptedVectorIndex[i] = oneVectorIndex;
			}
			
			this.receipt.setVerificationCode(oneVectorIndex, i);
			
		}
		return this.receipt;
	}

	public IMPValidityProof getValidityProof() {
		try{
			this.validity = new MPValidityProof(this.numberOfCandidates);
			
			ElGamalEncryption[][] voteEnc = this.voteEnc.getEncryptedVote();	
			
			BigInteger lambda = this.param.getLambda();
			BigInteger q=this.param.getQ();
			BigInteger p=this.param.getP();
			BigInteger challenge = this.receipt.getChallenge();
			
			BigInteger zeroVectorIndex;
			BigInteger[] zeroVector;
			BigInteger[] oneVector;
			BigInteger[] subVector;
			
			
			BigInteger sumFactor = BigInteger.ZERO;
			CGS97BallotValidity proof;
			boolean yesVote;
			ElGamalVerifiableEncryption vEnc;
			ElGamalPublicKey kpub = this.param.getPublicKey();
			BigInteger m;
			BigInteger mpG = this.param.getMP_G();
			BigInteger mpGInv = this.param.getMP_GInv();
			String hashFunction = "SHA-1";
			
			BigInteger canonicalTransformationFactor;
			ElGamalEncryption[] subVectorEnc;
			final BigInteger TWO = new BigInteger("2"); 
			ElGamalEncryption canonicalVote;
			BigInteger aux;
			BigInteger encryptionFactor;
			BigInteger auxInverse = q.subtract(TWO);
			BigInteger subtractionValue;
			
			for(int i=0; i<this.numberOfCandidates; i++)
			{
				//compute canonical vote	
				oneVector = this.param.getOneVector(this.encryptedVectorIndex[i]);
				zeroVectorIndex = challenge.subtract(
						this.encryptedVectorIndex[i]).mod(lambda);
				zeroVector = this.param.getZeroVector(zeroVectorIndex);
	
				
				subVector = MP2Util.vectorSubtraction(oneVector, zeroVector, q);
				subVectorEnc = MP2Util.vectorSubtraction(voteEnc[i], zeroVector, p, q, mpG);
				
				if(subVector[0].equals(BigInteger.ZERO))
				{
					canonicalTransformationFactor = subVector[1].modInverse(q);
					canonicalVote = MP2Util.multiplyByClearTextValue(subVectorEnc[1], 
							canonicalTransformationFactor, p);
					encryptionFactor = this.encryptionFactors[i][1];
					subtractionValue = subVector[1];
				} else {
					canonicalTransformationFactor = subVector[0].modInverse(q);
					canonicalVote = MP2Util.multiplyByClearTextValue(subVectorEnc[0],
							canonicalTransformationFactor, p);
					encryptionFactor = this.encryptionFactors[i][0];
					subtractionValue = subVector[0];
				}
				
				canonicalVote = MP2Util.multiplyByClearTextValue(canonicalVote, TWO, p);
				aux = canonicalVote.Y.multiply(param.getMP_GInv());
				canonicalVote = new ElGamalEncryption(canonicalVote.X, aux.mod(p));
				
				//compute encryption factor;
				
				BigInteger subInv = subtractionValue.modPow(auxInverse, q);
				BigInteger canonicalFactor = subInv.multiply(encryptionFactor).mod(q); 
				canonicalFactor = canonicalFactor.multiply(TWO).mod(q);
				
				vEnc = new ElGamalVerifiableEncryption(canonicalVote, canonicalFactor);
				
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
				
				sumFactor = sumFactor.add(canonicalFactor);
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
