package gsd.inescid.markpledge2;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;

import gsd.inescid.crypto.ElGamalPublicKey;
import gsd.inescid.math.algebra.matrix.MatrixUtil;

public class MP2Parameters {
	public static final BigInteger TWO = new BigInteger("2"); //public because it is not available in the BigInteger class
	public static final BigInteger FOUR = new BigInteger("4"); //public because it is not available in the BigInteger class
	private static final BigInteger ONE = BigInteger.ONE;
	
	public final ElGamalPublicKey PUBLIC_KEY;
	
	/** SO(2,q) generator */
	public final BigInteger [][] SO2Q_GENERATOR;
	
	/** SO2qOrder = q-1 **/
	public final BigInteger SO2Q_ORDER; 
	
	/** FOUR_MULT_FACTOR * 4 = SO2qOrder/lambda **/
	public final BigInteger FOUR_MULT_FACTOR; 
	
	/** LAMBDA_MULTIPLIER = SO2qOrder/lambda = FOUR_MULT_FACTOR * 4 **/
	public final BigInteger LAMBDA_MULTIPLIER; 
	
	/** lambda = SO2qOrder/(4 * FOUR_MULT_FACTOR) **/
	public final BigInteger LAMBDA; 
	
	
	public MP2Parameters (BigInteger[][] SO2qGenerator, BigInteger SO2qOrder, BigInteger fourMultFactor, BigInteger lambda, ElGamalPublicKey kpub)
	{
		this.PUBLIC_KEY = kpub;
		this.SO2Q_GENERATOR = SO2qGenerator;
		this.SO2Q_ORDER = SO2qOrder;
		this.FOUR_MULT_FACTOR = fourMultFactor;
		this.LAMBDA = lambda;
		this.LAMBDA_MULTIPLIER = FOUR.multiply(FOUR_MULT_FACTOR);
	}
	
	public MP2Parameters (MP2ElGamalKeyParameters mp2KeyParam, ElGamalPublicKey kpub)
	{
		this.PUBLIC_KEY = kpub;
		this.SO2Q_GENERATOR = mp2KeyParam.SO2qGenerator;
		this.SO2Q_ORDER = mp2KeyParam.SO2qOrder;
		this.FOUR_MULT_FACTOR = mp2KeyParam.FOUR_MULT_FACTOR;
		this.LAMBDA = mp2KeyParam.lambda;
		this.LAMBDA_MULTIPLIER = FOUR.multiply(FOUR_MULT_FACTOR);
	}
	
	private BigInteger[] getVector(BigInteger index)
	{
		try {
			BigInteger[][] m = MatrixUtil.rSO2qModPow(SO2Q_GENERATOR, index, PUBLIC_KEY.q);
			return m[0];
		} catch (InvalidAlgorithmParameterException e) {
			// This should not happen
			e.printStackTrace();
			return null;
		}
	}
	
	public final BigInteger[] getYesVector(BigInteger index)
	{
		index = ((index.multiply(LAMBDA_MULTIPLIER)).subtract(ONE)).mod(SO2Q_ORDER);
		return getVector(index);
	}
	
	public final BigInteger[] getNoVector(BigInteger index)
	{
		index = ((index.multiply(LAMBDA_MULTIPLIER)).add(ONE)).mod(SO2Q_ORDER);
		return getVector(index);
	}
	
	public final BigInteger[] getTestVector(BigInteger index)
	{
		index = (index.multiply(TWO).multiply(FOUR_MULT_FACTOR)).mod(SO2Q_ORDER);
		return getVector(index);
	}
	
}
