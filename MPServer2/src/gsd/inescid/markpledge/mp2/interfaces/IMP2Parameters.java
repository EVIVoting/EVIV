package gsd.inescid.markpledge.mp2.interfaces;

import gsd.inescid.markpledge.interfaces.IMPParameters;

import java.math.BigInteger;

public interface IMP2Parameters extends IMPParameters {

	public static final BigInteger TWO = new BigInteger("2"); //because it is not available in the BigInteger class
	public static final BigInteger FOUR = new BigInteger("4"); //because it is not available in the BigInteger class

	/** SO(2,q) generator */
	public BigInteger [][] getSO2qGenerator();
	
	/** SO2qOrder **/
	public BigInteger getSO2qOrder(); 
	
	/** lambda = SO2qOrder/LAMBDA_MULTIPLIER **/
	public BigInteger getLambda(); 
	
	/** LAMBDA_MULTIPLIER = SO2qOrder/lambda **/
	public BigInteger getLambdaMultiplier(); 
	
	/** TEST_CLASS_LAMBDA_MULTIPLIER = LAMBDA_MULTIPLIER/2 **/
	public BigInteger getTestClassLambdaMultiplier(); 
	
	public BigInteger[] getOneVector(BigInteger index);
	public BigInteger[] getZeroVector(BigInteger index);
	public BigInteger[] getTestVector(BigInteger index);
	
	
	public void setSO2qGenerator(BigInteger[][] so2qGenerator);
	public void setSO2qOrder(BigInteger so2qOrder);
	public void setLambda(BigInteger lambda);
	public void setLambdaMultiplier(BigInteger lambdaMultiplier);
}
