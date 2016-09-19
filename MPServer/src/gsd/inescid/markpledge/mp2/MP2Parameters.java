package gsd.inescid.markpledge.mp2;

import gsd.inescid.crypto.ElGamalPublicKey;
import gsd.inescid.crypto.MP2ElGamalKeyParameters;
import gsd.inescid.markpledge.MPParameters;
import gsd.inescid.markpledge.mp2.interfaces.IMP2Parameters;
import gsd.inescid.math.algebra.matrix.MatrixUtil;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;

public class MP2Parameters extends MPParameters implements IMP2Parameters {

	private BigInteger[][] so2qGenerator;
	private BigInteger so2qOrder;
	private BigInteger lambda;
	private BigInteger lambdaMultiplier;
	private BigInteger testClassLambdaMultiplier;
	
	public MP2Parameters(){};
	
	public MP2Parameters(MP2ElGamalKeyParameters param, ElGamalPublicKey key, int alpha)
	{
		super(key, key.g, alpha, 0); //vcodeLength = 0;
		setSO2qGenerator(param.SO2qGenerator);
		setSO2qOrder(param.SO2qOrder);
		setLambda(param.lambda);
		setLambdaMultiplier(MP2ElGamalKeyParameters.FOUR.multiply(param.FOUR_MULT_FACTOR));
	};
	
	public MP2Parameters (ElGamalPublicKey key, BigInteger mpG, int alpha, int voteCodeLength,
			BigInteger[][] so2qGenerator, BigInteger so2qOrder, BigInteger lambda, 
			BigInteger lambdaMultiplier)
	{
		super(key, mpG, alpha, voteCodeLength);
		setSO2qGenerator(so2qGenerator);
		setSO2qOrder(so2qOrder);
		setLambda(lambda);
		setLambdaMultiplier(lambdaMultiplier);
		
	}
	
	
	
	public BigInteger[][] getSO2qGenerator() {
		return this.so2qGenerator;
	}

	
	public BigInteger getSO2qOrder() {
		return this.so2qOrder;
	}

	
	public BigInteger getLambda() {
		return this.lambda;
	}

	
	public BigInteger getLambdaMultiplier() {
		return this.lambdaMultiplier;
	}

	
	public BigInteger getTestClassLambdaMultiplier() {
		return this.testClassLambdaMultiplier;
	}

	
	public void setSO2qGenerator(BigInteger[][] so2qGenerator) {
		this.so2qGenerator = so2qGenerator;
		
	}


	
	public void setSO2qOrder(BigInteger so2qOrder) {
		this.so2qOrder = so2qOrder;
	}


	
	public void setLambda(BigInteger lambda) {
		this.lambda = lambda;		
	}


	
	public void setLambdaMultiplier(BigInteger lambdaMultiplier) {
		this.lambdaMultiplier = lambdaMultiplier;
		this.testClassLambdaMultiplier = this.lambdaMultiplier.divide(TWO);
	}
	
	
	private BigInteger[] getVector(BigInteger index)
	{
		//TODO update multiplication method
		//System.out.println("Index: " + index.toString(16));
		try {
			BigInteger[][] m = MatrixUtil.rSO2qModPow(this.so2qGenerator, index, getQ());
			return m[0];
		} catch (InvalidAlgorithmParameterException e) {
			// This should not happen
			e.printStackTrace();
			return null;
		}
	}
	
	
	public final BigInteger[] getOneVector(BigInteger index)
	{
		if(index.equals(BigInteger.ZERO))
			index = this.so2qOrder.subtract(BigInteger.ONE);
		else	
			index = ((index.multiply(this.lambdaMultiplier)).subtract(BigInteger.ONE));//.mod(this.so2qOrder);
		return getVector(index);
	}
	
	public final BigInteger[] getZeroVector(BigInteger index)
	{
		index = ((index.multiply(this.lambdaMultiplier)).add(BigInteger.ONE));//.mod(this.so2qOrder);
		return getVector(index);
	}
	
	public final BigInteger[] getTestVector(BigInteger index)
	{
		index = (index.multiply(this.testClassLambdaMultiplier));//.mod(this.so2qOrder);
		return getVector(index);
	}

}
