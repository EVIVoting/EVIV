package gsd.inescid.markpledge.smartclient.connection;

import gsd.inescid.markpledge.MarkPledgeType;
import gsd.inescid.markpledge.interfaces.IMPReceipt;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;
import gsd.inescid.markpledge.mp2.MP2Util;
import gsd.inescid.markpledge.mp2.interfaces.IMP2Parameters;
import gsd.inescid.markpledge.smartclient.CardConstants;
import gsd.inescid.markpledge.smartclient.CardUtil;
import gsd.inescid.markpledge.smartclient.apdu.ActionAPDU;

import java.math.BigInteger;

public class MP2WithHelpCardConnection extends MP2AbstractCardConnection{

	protected IMPReceipt receipt;
	protected BigInteger challenge;
	protected IMP2Parameters param; 
	
	public MP2WithHelpCardConnection(IMP2Parameters param,
			boolean showPerformanceTimes,ISmartCardInterface cardConnection) 
	{
		super(param.getPLengthInBytes(), param.getQLengthInBytes(), 
				param.getVoteCodeByteLength(), CardConstants.ALPHA_MAX_VALUE/8, showPerformanceTimes, cardConnection,
				MarkPledgeType.MP2_WITH_HELP);
		this.param = param;
	}
	
	
	public IMPReceipt getVoteReceipt(BigInteger candidateVoteCode, BigInteger chal, int numberOfCandidates) throws CardException
	{
		this.challenge = chal;
		this.receipt = super.getVoteReceipt(candidateVoteCode, chal, numberOfCandidates);
		return this.receipt;
	}

		
	public IMPValidityProof getValidity(int numberOfCandidates) throws CardException
	{
		long start, end;
		//create canonical vote with help
		BigInteger[] oneVector;
		BigInteger[] zeroVector;
		BigInteger[] subtractionVector;
		BigInteger[] verificationCodes;
		BigInteger zeroVectorIndex;
		BigInteger canonicalTransformationFactor;
		BigInteger q,p;
		BigInteger lambda;
		BigInteger subtractionHelp;
		BigInteger mpG;
		BigInteger aux;
		int chosenElement,pLength, qLength;
		byte[] data;
		
		start = System.currentTimeMillis();
		p = this.param.getP();
		q = this.param.getQ();
		lambda = this.param.getLambda();
		mpG = this.param.getMP_G();
		pLength = this.param.getPLengthInBytes();
		qLength = this.param.getQLengthInBytes();
		
		verificationCodes = this.receipt.getVerificationCodes();
		for(int i=0; i<numberOfCandidates; i++)
		{
			oneVector = this.param.getOneVector(verificationCodes[i]);
			zeroVectorIndex = this.challenge.subtract(verificationCodes[i]).mod(lambda);
			zeroVector = this.param.getZeroVector(zeroVectorIndex);
			subtractionVector = MP2Util.vectorSubtraction(oneVector, zeroVector, q); 
			if(subtractionVector[0].equals(BigInteger.ZERO))
			{
				chosenElement = 1; 
				canonicalTransformationFactor = subtractionVector[1].mod(q).modInverse(q);
			} else {
				chosenElement = 0; 
				canonicalTransformationFactor = subtractionVector[0].mod(q).modInverse(q);
			}
			aux = q.subtract(zeroVector[chosenElement]);
			subtractionHelp = mpG.modPow(aux, p);
			ActionAPDU.CREATE_MP2_CANONICAL_VOTE_WITH_HELP.setP1P2(i, chosenElement);
			data = CardUtil.concatenateArrays(CardUtil.bigIntegerToByteArray(subtractionHelp, pLength),
										  CardUtil.bigIntegerToByteArray(canonicalTransformationFactor, qLength));
			sendReceiveAPDU(ActionAPDU.CREATE_MP2_CANONICAL_VOTE_WITH_HELP.getAPDUBytes(data));
		}
		end = System.currentTimeMillis();
		if(PERFORMANCE_TIMES)
			System.out.println("Canonical vote transformation (with help): " + (end-start));
		
		return super.getValidity(numberOfCandidates); 
	}
}
