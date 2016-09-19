#ifndef UTIL_H_INCLUDED
#define UTIL_H_INCLUDED

#include "DataStructures.h"

/*
void printArray(unsigned char* a, int len);
void printParam(void);
*/

/**
 * Create Q_LENGTH random bytes and stores them in the array toFill
 * q: the cryptographic modulus q
 * toFill: array to store the Q_LENGTH random bytes. The value is allways less than the cryptographic modulus q
 */
 void fillRandomLessThanQ(unsigned char* q, unsigned char* toFill);

/**
 * Create ALPHA_BITS_BYTE_LENGTH random bytes and stores them in the array toFill
 * It is assumed that ALPHA_BITS_BYTE_LENGTH is <= 8 bytes
 * toFill: array to store the random bytes.
 */
 void getRandomAlphaBits(unsigned char* toFill);

/**
 * Create a random value less than lambda and stores it in the array toFill.
 * It is assumed that LAMBDA_LENGTH = ALPHA_BITS_BYTE_LENGTH is <= 8 bytes
 * 
 * lambda: the MP2 lambda parameter. 
 * toFill: array to store the random bytes. The value is allways less than lambda.
 *
 */
 void getRandomLessThanLambda(unsigned char* lambda, unsigned char* toFill);


  /**
  * Compare the unsigned array values.
  * op1: first array
  * op2: second array
  * length: the length of the arrays in bytes.
  * Return: compares the first length bytes of the arrays and return
  *				1 if op1 > op2
				0 if op1 == op2
				-1 if op1 < op2
  */
 int compare (unsigned char* op1, unsigned char* op2, int length);

 /**
 * Verify if length bytes are zero.
 * return 1 of length bytes starting at v are zero; return 0 otherwise
 */
int isZero(unsigned char* v, int length);


/**
 * Perform subtraction modulus mod
 * res = op1 - op2 modulos mod
 * assumes that res, op1, op2 and mod have length = Q_LENGTH
 */
void subModQ(unsigned char* res, unsigned char* op1, unsigned char* op2, unsigned char* mod);

/**
 * Perform subtraction modulus mod
 * res = op1 - op2 modulos mod
 * assumes that res, op1, op2 and mod have length = LAMBDA_LENGTH
 */
void subModLambda(unsigned char* res, unsigned char* op1, unsigned char* op2, unsigned char* mod);


/******************************************************************/
/** Matrix multiplication SO(2,q)**/
/******************************************************************/
void matrixModMultSO2Q(Matrix* ma, Matrix* mb, Matrix* mr, unsigned char* modulus);

/******************************************************************
 * Matrix 2x2 in Z_q exponentiation by squaring
 *
 * Assumes: length of values in matrix,result,exponent and mudulus = Q_LENGTH
 * IMPORTANT NOTE: it uses the global matrices mA, mR and mAux in the computations
/******************************************************************/
void matrixModPowBySquaring(Matrix* ma, Matrix* mr, unsigned char* exponent, unsigned char* modulus);


#endif //UTIL_H_INCLUDE
