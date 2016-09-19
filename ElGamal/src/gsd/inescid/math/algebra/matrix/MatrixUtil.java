package gsd.inescid.math.algebra.matrix;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;


/**
 * This class provides useful modular matrix operations. 
 * No validation of the parameters is performed so check out for
 * the ArrayIndexOutOfBoundsException and any other unexpected
 * result from the wrong matrix parameters size.   
 * 
 * This class assumes that the matrix as column index (col)
 * and a row index (row) which are used in the following manner: matrix[row][col]
 * 
 * @author Rui
 *
 */
public class MatrixUtil {

	/**
	 * Modular matrix addition
	 * @param A 
	 * @param B 
	 * @param m modulus
	 * @return A + B mod m
	 */
	public static BigInteger[][] matrixAddition (BigInteger[][] A, BigInteger[][] B, BigInteger m)
	{
		BigInteger[][] result = new BigInteger[A.length][A[0].length];
		
		for(int row = 0; row < result.length; row++)
		{
			for(int col = 0; col < result[0].length; col++)
				result[row][col] = (A[row][col].add(B[row][col])).mod(m);
		}
		return result;
	}
	
	
	/**
	 * Modular matrix by scalar multiplication
	 * @param A 
	 * @param n scalar value
	 * @param m modulus
	 * @return A * n mod m
	 */
	public static BigInteger[][] matrixMultiplication (BigInteger[][] A, BigInteger n, BigInteger m)
	{
		BigInteger[][] result = new BigInteger[A.length][A[0].length];
		
		for(int row = 0; row < result.length; row++)
		{
			for(int col = 0; col < result[0].length; col++)
				result[row][col] = (A[row][col].multiply(n)).mod(m);
		}
		return result;
	}
	
	/**
	 * Modular matrix by matrix multiplication
	 * @param A 
	 * @param B
	 * @param m modulus
	 * @return A * B mod m
	 */
	public static BigInteger[][] matrixMultiplication (BigInteger[][] A, BigInteger[][] B, BigInteger m)
	{
		BigInteger[][] result = new BigInteger[A.length][A[0].length];
		
		for(int row = 0; row < result.length; row++)
		{
			for(int col = 0; col < result[0].length; col++)
				result[row][col] = sumProductRowCol(A, B, row,col,m);
		}
		return result;
	}

	/**
	 * SumProduct of a row by a column (subroutine of matrix multiplication)
	 * @param A
	 * @param B
	 * @param Arow
	 * @param Bcol
	 * @param m
	 * @return sumproduct of row Arow by column Bcol
	 */
	private static BigInteger sumProductRowCol(BigInteger[][] A, BigInteger[][] B, int Arow, int Bcol, BigInteger m)
	{
		BigInteger sum = BigInteger.ZERO;
		BigInteger product;
		for(int i=0; i < A[0].length; i++)
		{
			product = A[Arow][i].multiply(B[i][Bcol]);
			sum = sum.add(product).mod(m);
		}
		
		return sum;
	}

	/**
	 * Modular matrix exponentiation
	 * @param A 
	 * @param e exponent
	 * @param m modulus
	 * @return A^e mod m
	 */
	public static BigInteger[][] matrixModPow (BigInteger[][] A, BigInteger e, BigInteger m)
	{
		if(e.compareTo(BigInteger.ZERO)==0)
		{
			BigInteger[][] result = new BigInteger[2][2];
			result[0][0] = BigInteger.ONE;
			result[0][1] = BigInteger.ZERO;
			result[1][0] = BigInteger.ZERO;
			result[1][1] = BigInteger.ONE;
			return result;
		}
		
		BigInteger[][] result = A;
		
		BigInteger i = BigInteger.valueOf(2); 
		while(i.compareTo(e) <= 0)
		{
			result = MatrixUtil.matrixMultiplication(result, A, m);
			i = i.add(BigInteger.ONE);
		}
		
		result[0][0] = result[0][0].mod(m);
		result[0][1] = result[0][1].mod(m);
		result[1][0] = result[1][0].mod(m);
		result[1][1] = result[1][1].mod(m);
		return result;
	}
	
	
	/**
	 * Class created to temporary contain the results of the recursive matrix power result
	 */
	private static class RecursiveMatrixPowResult{
		BigInteger[][] matrixExponentiation;
		BigInteger remainingExponent;
	
		RecursiveMatrixPowResult(BigInteger[][] m, BigInteger e)
		{
			this.matrixExponentiation = m;
			this.remainingExponent = e;
		}
	}
	
	
	/**
	 * Recursive matrix exponentiation of a matrix
	 * using the exponentiation by squaring technique. (http://en.wikipedia.org/wiki/Exponentiation_by_squaring)
	 * 
	 * @param matrix
	 * @param e exponent
	 * @param q modulus
	 * @return matrix ^ e mod q 
	 * @throws InvalidAlgorithmParameterException if e < 0
	 */
	public static BigInteger[][] rModPow(BigInteger[][] matrix, BigInteger e, BigInteger q) throws InvalidAlgorithmParameterException
	{
		if(e.compareTo(BigInteger.ZERO)<0)
			throw new InvalidAlgorithmParameterException("Invalid exponent: must be >= 1.");
		
		if(e.compareTo(BigInteger.ZERO)==0)
		{
			BigInteger[][] result = new BigInteger[2][2];
			result[0][0] = BigInteger.ONE;
			result[0][1] = BigInteger.ZERO;
			result[1][0] = BigInteger.ZERO;
			result[1][1] = BigInteger.ONE;
			return result;
		}
		
		RecursiveMatrixPowResult res = rStepModPow(matrix, BigInteger.ONE, e, q);
		return res.matrixExponentiation;
	}
	
	
	/**
	 * Recursive step of a matrix modular exponentiation
	 * 
	 * @param matrixPower the base matrix^currentPower mod q
	 * @param currentPower
	 * @param desiredPower
	 * @param q modulus
	 * @return intermediate matrix power result
	 * @throws InvalidAlgorithmParameterException if desired exponent < 1
	 */
	private static RecursiveMatrixPowResult rStepModPow(BigInteger[][] matrixPower, BigInteger currentPower, BigInteger desiredPower, BigInteger q) throws InvalidAlgorithmParameterException
	{
		BigInteger nextPower = currentPower.multiply(BigInteger.valueOf(2));
		RecursiveMatrixPowResult res;
		
		//recursive condition
		if (nextPower.compareTo(desiredPower)>0) //this is the last recursive step
		{
			res = new RecursiveMatrixPowResult(matrixPower, desiredPower.subtract(currentPower));
			return res;
		
		} else 
		{
			res = rStepModPow(MatrixUtil.matrixMultiplication(matrixPower, matrixPower, q), nextPower, desiredPower, q);
			if (currentPower.compareTo(res.remainingExponent)<=0)
			{
				res.matrixExponentiation = MatrixUtil.matrixMultiplication(matrixPower, res.matrixExponentiation, q);
				res.remainingExponent = res.remainingExponent.subtract(currentPower);
			}	
			return res;
		}
	}
	
	
	
	/**
	 * Matrix exponentiation of a matrix of the SO(2,q) group
	 * 
	 * @param matrix
	 * @param e exponent
	 * @param q modulus
	 * @return matrix ^ e mod q
	 * @throws InvalidAlgorithmParameterException 
	 * @throws InvalidAlgorithmParameterException if e < 0
	 */
	public static BigInteger[][] SO2qModPow(BigInteger[][] matrix, BigInteger e, BigInteger q) throws InvalidAlgorithmParameterException
	{
		if(e.compareTo(BigInteger.ZERO)<0)
			throw new InvalidAlgorithmParameterException("Invalid exponent: must be >= 0.");
		
		if(e.compareTo(BigInteger.ZERO)==0)
		{
			BigInteger[][] result = new BigInteger[2][2];
			result[0][0] = BigInteger.ONE;
			result[0][1] = BigInteger.ZERO;
			result[1][0] = BigInteger.ZERO;
			result[1][1] = BigInteger.ONE;
			return result;
		}
			
		
		BigInteger[][] result = new BigInteger[2][2];
		BigInteger[][] aux = new BigInteger[2][2];
		result[0][0] = matrix[0][0];
		result[0][1] = matrix[0][1];
		result[1][0] = matrix[1][0];
		result[1][1] = matrix[1][1];
		
		while(e.compareTo(BigInteger.ONE)>0)
		{
			aux[0][0] = result[0][0];
			aux[0][1] = result[0][1];
			aux[1][0] = result[1][0];
			aux[1][1] = result[1][1];
			
			
			result[0][0] = matrix[0][0].multiply(aux[0][0]).mod(q).add(
					       matrix[0][1].multiply(aux[1][0])).mod(q);

			result[0][1] = matrix[0][0].multiply(aux[0][1]).mod(q).add(
			  	       	   matrix[0][1].multiply(aux[1][1])).mod(q);
			
			result[1][0] = q.subtract(result[0][1]).mod(q);
			result[1][1] = result[0][0];
			       
			e = e.subtract(BigInteger.ONE);
		}
		
		return result;
	}

	
	
	
	/**
	 * Recursive matrix exponentiation of a matrix of the SO(2,q) group
	 * using the exponentiation by squaring technique. (http://en.wikipedia.org/wiki/Exponentiation_by_squaring)
	 * 
	 * @param matrix
	 * @param e exponent
	 * @param q modulus
	 * @return matrix ^ e mod q 
	 * @throws InvalidAlgorithmParameterException if e < 0
	 */
	public static BigInteger[][] rSO2qModPow(BigInteger[][] matrix, BigInteger e, BigInteger q) throws InvalidAlgorithmParameterException
	{
		if(e.compareTo(BigInteger.ZERO)<0)
			throw new InvalidAlgorithmParameterException("Invalid exponent: must be >= 0.");
		
		if(e.compareTo(BigInteger.ZERO)==0)
		{
			BigInteger[][] result = new BigInteger[2][2];
			result[0][0] = BigInteger.ONE;
			result[0][1] = BigInteger.ZERO;
			result[1][0] = BigInteger.ZERO;
			result[1][1] = BigInteger.ONE;
			return result;
		}
		
		RecursiveMatrixPowResult res = rStepSO2qModPow(matrix, BigInteger.ONE, e, q);
		return res.matrixExponentiation;
	}
	

	
	/**
	 * Recursive step of a SO2q matrix modular exponentiation
	 * 
	 * @param matrixPower the base matrix^currentPower mod q
	 * @param currentPower
	 * @param desiredPower
	 * @param q modulus
	 * @return intermediate matrix power result
	 * @throws InvalidAlgorithmParameterException if desired exponent < 1
	 */
	private static RecursiveMatrixPowResult rStepSO2qModPow(BigInteger[][] matrixPower, BigInteger currentPower, BigInteger desiredPower, BigInteger q) throws InvalidAlgorithmParameterException
	{
		BigInteger nextPower = currentPower.multiply(BigInteger.valueOf(2));
		RecursiveMatrixPowResult res;
		
		//recursive condition
		if (nextPower.compareTo(desiredPower)>0) //this is the last recursive step
		{
			res = new RecursiveMatrixPowResult(matrixPower, desiredPower.subtract(currentPower));
			return res;
		
		} else 
		{
			res = rStepSO2qModPow(MatrixUtil.SO2qModPow(matrixPower, BigInteger.valueOf(2), q), nextPower, desiredPower, q);
			if (currentPower.compareTo(res.remainingExponent)<=0)
			{
				res.matrixExponentiation = MatrixUtil.matrixMultiplication(matrixPower, res.matrixExponentiation, q);
				res.remainingExponent = res.remainingExponent.subtract(currentPower);
			}	
			return res;
		}
	}
	
	


	/**
	 * Creates the String representation of the matrix m
	 * Assumes a non empty vector matrix.
	 * 
	 * @param m
	 * @return String representation of matrix m
	 */
	public static String toString(BigInteger[][] m)
	{
		String result="[" + toString(m[0]);
		for(int i=1; i<m.length; i++)
			result = result + "\n " + toString(m[i]);
		result = result + "]";
		return result;
	}
	
	
	/**
	 * Creates the String representation of the vector m
	 * Assumes a non empty vector.
	 * 
	 * @param v
	 * @return String representation of vector v
	 */
	public static String toString(BigInteger[] v)
	{
		String result="[" + v[0].toString(10);
		for(int i=1; i<v.length; i++)
			result = result + ", " + v[i].toString(10);
		result = result + "]";
		return result;
	}
	

	/* power by squaring following the wikipedia algorithm*/
	public static void matrixModMultSO2Q(Matrix ma, Matrix mb, Matrix mr, BigInteger modulus)
	{
		BigInteger aux1, aux2;
		aux1 = ma.a.multiply(mb.a).mod(modulus);
		aux2 = ma.b.multiply(mb.c).mod(modulus);
		mr.a = aux1.add(aux2).mod(modulus);
		mr.d = mr.a;
		
		aux1 = ma.a.multiply(mb.b).mod(modulus);
		aux2 = ma.b.multiply(mb.d).mod(modulus);
		mr.b = aux1.add(aux2).mod(modulus);
		mr.c = modulus.subtract(mr.b);
	}
	
	public static Matrix matrixModExpSO2Q(Matrix m, BigInteger exponent, BigInteger modulus)
	{
		Matrix auxA = new Matrix();
		Matrix auxR = new Matrix();
		Matrix ma = new Matrix();
		Matrix mr = new Matrix();
		Matrix temp;
		
		ma.a = m.a;
		ma.b = m.b;
		ma.c = m.c;
		ma.d = m.d;
		
		if(exponent.testBit(0))
		{
			mr.a = ma.a;
			mr.b = ma.b;
			mr.c = ma.c;
			mr.d = ma.d;
		}
				
		exponent = exponent.shiftRight(1);
		while(!exponent.equals(BigInteger.ZERO))
		{
			matrixModMultSO2Q(ma, ma, auxA, modulus);
			temp = ma;
			ma = auxA;
			auxA = temp;
			
			if(exponent.testBit(0))
			{
				matrixModMultSO2Q(ma, mr, auxR, modulus);
				temp = mr;
				mr = auxR;
				auxR = temp;
			}
			exponent = exponent.shiftRight(1);
		}
		return mr;
	}
	
	
	
	private static void matrixModMultSO2QT(Matrix ma, Matrix mb, Matrix mr, BigInteger mod)
	{	
		BigInteger ri1; 
		BigInteger ri2; 
		BigInteger aux;
		
		/** mrA */
		//MathUtilMP3.modMult(ma.a, mb.a, mod, ri1, aux, rsaCipher);
		ri1 = ma.a.multiply(mb.a).mod(mod);
		//MathUtilMP3.modMult(ma.b, mb.c, mod, ri2, aux, rsaCipher);
		ri2 = ma.b.multiply(mb.c).mod(mod);
		
		//MathUtilMP3.addMod(ri1, ri2 , mr.a, mod);
		mr.a = ri1.add(ri2).mod(mod);
		
		/** mrD */
		//Util.arrayCopyNonAtomic(mr.a, (short)0, mr.d, (short)0, MP3Constants.Q_SIZE);
		mr.d = mr.a;
		
		/** mrB */
		//MathUtilMP3.modMult(ma.a, mb.b, mod, ri1, aux, rsaCipher);
		ri1 = ma.a.multiply(mb.b).mod(mod);
		//MathUtilMP3.modMult(ma.b, mb.d, mod, ri2, aux, rsaCipher);
		ri2 = ma.b.multiply(mb.d).mod(mod);
		//MathUtilMP3.addMod(ri1, ri2 , mr.b, mod);
		mr.b = ri1.add(ri2).mod(mod);
		
		/** mrC */
		//MathUtilMP3.subtract(mod, mr.b, mr.c);
		mr.c = mod.subtract(mr.b);
	}
	
	public static Matrix matrixModExpT(Matrix m, BigInteger exp, BigInteger mod)
	{
		Matrix mr = new Matrix(); 
		Matrix mAux = new Matrix();
		Matrix ma = new Matrix();
		Matrix temp;
		
		//byte[] exponent = new byte[exp.length];
		byte[] exponent = exp.toByteArray();
		
		byte iExponentByte = (byte)(exponent.length - 1);
		byte iExponentBit = 0;
		short auxByte;// = (short)(exponent[iExponentByte] & 0xFF);
		
		//Util.arrayCopyNonAtomic(exp, (short)0, exponent, (short)0, (short)exp.length);
		auxByte = (short)(exponent[iExponentByte] & 0xFF);
		/*
		Util.arrayCopyNonAtomic(m.a, (short)0, ma.a, (short)0, MP3Constants.Q_SIZE);
		Util.arrayCopyNonAtomic(m.b, (short)0, ma.b, (short)0, MP3Constants.Q_SIZE);
		Util.arrayCopyNonAtomic(m.c, (short)0, ma.c, (short)0, MP3Constants.Q_SIZE);
		Util.arrayCopyNonAtomic(m.d, (short)0, ma.d, (short)0, MP3Constants.Q_SIZE);
		 */
		ma.a = m.a;
		ma.b = m.b;
		ma.c = m.c;
		ma.d = m.d;
		
		if((auxByte & 0x01) == 1)
		{/*
			Util.arrayCopyNonAtomic(ma.a, (short)0, mr.a, (short)0, MP3Constants.Q_SIZE);
			Util.arrayCopyNonAtomic(ma.b, (short)0, mr.b, (short)0, MP3Constants.Q_SIZE);
			Util.arrayCopyNonAtomic(ma.c, (short)0, mr.c, (short)0, MP3Constants.Q_SIZE);
			Util.arrayCopyNonAtomic(ma.d, (short)0, mr.d, (short)0, MP3Constants.Q_SIZE);
			*/
			mr.a = ma.a;
			mr.b = ma.b;
			mr.c = ma.c;
			mr.d = ma.d;
		}
		
		
		auxByte >>>= 1;
		exponent[iExponentByte] = (byte) auxByte;
	
		//boolean flag = true;
		while(!isZero(exponent))// && flag)
		{
			iExponentBit++;
			if(iExponentBit == 8)
			{
				iExponentBit=0;
				iExponentByte--;
				auxByte = (short)(exponent[iExponentByte] & 0xFF);
			}
			
			
			matrixModMultSO2QT(ma, ma, mAux, mod);
			temp = ma;
			ma = mAux;
			mAux = temp;
			
			if((auxByte & 0x01) == 1)
			{
				matrixModMultSO2QT(ma, mr, mAux, mod);
				temp = mr;
				mr = mAux;
				mAux = temp;
			}
			
			auxByte >>>= 1;
			exponent[iExponentByte] = (byte) auxByte;
			
			//flag = false;
		}
		
		return mr;
		
	}
	
	
	private static boolean isZero(byte[] v)
	{
		for(short i=(short)(v.length-1); i>=0; i--)
			if(v[i]!=0)
				return false;
		return true;
	}
	
	
	
	
}
