package gsd.inescid.markpledge.mp1;

import gsd.inescid.crypto.ElGamalEncryption;
import gsd.inescid.crypto.ElGamalPublicKey;
import gsd.inescid.markpledge.ArraysUtil;
import gsd.inescid.markpledge.MPAbstractVoteReceiptFactory;
import gsd.inescid.markpledge.MPEncryptedVote;
import gsd.inescid.markpledge.MPReceipt;
import gsd.inescid.markpledge.MarkPledgeType;
import gsd.inescid.markpledge.interfaces.IMPEncryptedVote;
import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.interfaces.IMPReceipt;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;
import gsd.inescid.markpledge.smartclient.CardUtil;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Random;

public class MP1VoteReceiptFactory extends MPAbstractVoteReceiptFactory {

	protected byte[][] verificationCodes;
	protected BigInteger[][] BMPencryptionFactors;
	
	
	public MP1VoteReceiptFactory(IMPParameters param) {
		super(MarkPledgeType.MP1, param);
	}

	@Override
	public void init(int numberOfCandidates) {
		super.init(numberOfCandidates);
		createRandomInitializationData();
	}
	
	protected void createRandomInitializationData()
	{
		BigInteger two = BigInteger.valueOf(2);
		BigInteger aux = two.pow(this.param.getAlpha());
		int alphaBitLength = aux.bitLength()-1;
		BigInteger q = this.param.getQ();
		int qBits = this.param.getQLengthInBytes() * 8; 
		
		//create BMP encryption factors
		this.BMPencryptionFactors = new BigInteger[this.numberOfCandidates][this.param.getAlpha()*2];
		for(int i=0; i<this.numberOfCandidates; i++)
			for(int k=0; k<this.BMPencryptionFactors[i].length; k++)
				this.BMPencryptionFactors[i][k] = 
					(new BigInteger(qBits, this.randomSource)).mod(q);
		
		//create verification codes
		this.verificationCodes = new byte[this.numberOfCandidates][];
		for(int i=0; i<this.verificationCodes.length; i++)
		{
			aux = new BigInteger(alphaBitLength, this.randomSource);
			this.verificationCodes[i] = CardUtil.bigIntegerToByteArray(aux, this.param.getAlphaByteLength());
		}
		
	}
	
	public BigInteger getPledge() {
		return new BigInteger(1, this.verificationCodes[this.yesVotePosition]);
	}
	
	public IMPEncryptedVote getEncryptedVote() 
	{
		this.voteEnc = new MPEncryptedVote(this.numberOfCandidates);
		ElGamalEncryption[] candidateEncryption;
		boolean ccodeBit;
		BigInteger ccode; 
		ElGamalPublicKey kpub = this.param.getPublicKey();
		BigInteger one = this.param.getMP_G();
		BigInteger zero = this.param.getMP_GInv();
		BigInteger m, mInv;
		
		
		for(int i=0; i<this.numberOfCandidates; i++)
		{
			ccode = new BigInteger(1, this.verificationCodes[i]);
			candidateEncryption = new ElGamalEncryption[this.param.getAlpha()*2];
			
			for(int iBMP = this.param.getAlpha()-1, k=0; iBMP >=0; k+=2, iBMP--)
			{
				ccodeBit = ccode.testBit(iBMP);
				
				//encrypt left part of the BMP
				if(ccodeBit) // encrypt "m = one"
				{
					m = one;
					mInv = zero;
				}
				else // encrypt "m = zero"
				{
					m = zero;
					mInv = one;
				}
				candidateEncryption[k] = kpub.encryptQOrderMessage(m, this.BMPencryptionFactors[i][k]);
				
				//encrypt right part of the BMP
				if(i==this.yesVotePosition) //encrypt same value
					mInv = m;
				candidateEncryption[k+1] = kpub.encryptQOrderMessage(mInv, this.BMPencryptionFactors[i][k+1]);
			
								
			}
			
			this.voteEnc.setCandidateVote(i, candidateEncryption);
		}
		
		setVoteHash();
		
		return this.voteEnc;
	}


	
	
	public IMPReceipt getReceipt(int selectedCandidateIndex,
			BigInteger challenge) 
	{
		this.receipt = new MPReceipt(this.numberOfCandidates);
		this.receipt.setChallenge(challenge);
				
		this.receipt.setRotation(getVoteRotation(selectedCandidateIndex));
		
		//verification codes calculus
		int alphaByteLength = this.param.getAlphaByteLength();
		int alpha = this.param.getAlpha();
		byte[] vcode;
		byte[] notVcode = new byte[alphaByteLength];
		byte[] chal = CardUtil.bigIntegerToByteArray(challenge, alphaByteLength);
		byte[] notChal = new byte[alphaByteLength];
		byte[] aux1 = new byte[alphaByteLength];
		byte[] aux2 = new byte[alphaByteLength];
		int nBytes;
		int nBits;
		byte clearFlag;
		
		System.arraycopy(chal, 0, notChal, 0, chal.length);
		ArraysUtil.negate(notChal);
		
		
				
		for(int i=0; i<this.numberOfCandidates; i++)
		{
			
			vcode = this.verificationCodes[i];
			System.arraycopy(vcode, 0, notVcode, 0, vcode.length);	
			ArraysUtil.negate(notVcode);
			
			if(this.yesVotePosition != i)
			{
				ArraysUtil.logicalAnd(vcode, notChal, aux1);
				ArraysUtil.logicalAnd(notVcode, chal, aux2);
				ArraysUtil.logicalOr(aux1, aux2, vcode);
			}
								
			//reduce to alpha bits
			nBytes = vcode.length - (alpha/8);
			nBits = alpha%8;
			if(nBits!=0)
			{
				clearFlag = (byte)0xFF;
				nBits = 8-nBits;
				clearFlag >>>= nBits;
				vcode[alpha/8] = (byte)(vcode[alpha/8] & clearFlag);
				nBytes--;
			}
						
			for(int k=vcode.length-1; nBytes > 0; nBytes--)
				vcode[k] = 0;
			
			this.receipt.setVerificationCode(new BigInteger(1,vcode), i);
		
		
			//receipt validity
			BigInteger[] validityFactors = new BigInteger[alpha];
			for(int a=alpha-1, iBMP=0; a>=0; a--, iBMP++)
			{
				if(challenge.testBit(a)) //right BMP element
					validityFactors[iBMP] = this.BMPencryptionFactors[i][iBMP*2+1];
				else
					validityFactors[iBMP] = this.BMPencryptionFactors[i][iBMP*2];
				
			}
			this.receipt.setValidity(validityFactors, i);
		}
		
		setReceiptHash();
		return this.receipt;
	}

	
	//MP1 does not have a (CGS97) validity proof
	public IMPValidityProof getValidityProof() {
		return null;
	}


}
