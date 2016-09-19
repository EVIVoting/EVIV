#include <string.h>
#include <multoscrypto.h>
#include <multosarith.h>
#include "MarkPledgeConstants.h"
#include "DataStructures.h"

#include <stdio.h>

/*
void printArray(unsigned char* a, int len)
{
	int i;
	for(i = 0; i<len; i++)
	{
		printf("%02x ", a[i]);

	}
	printf("\n");
}
*/

extern MarkPledgeParameters param;
extern Matrix mA,mAux,mR;


/*
void printParam(void)
{
	printf("Alpha: ");
	printArray(&param.alpha, 1);
	printf("P: ");
	printArray(param.kpub.p, 20);
	printf("Q: ");
	printArray(param.kpub.q, 20);
	printf("G: ");
	printArray(param.kpub.g, 20);
	printf("H: ");
	printArray(param.kpub.h, 20);
	printf("MPG: ");
	printArray(param.kpub.mpG, 20);
	printf("MPGInv: ");
	printArray(param.kpub.mpGInv, 20);
	printf("lambda: ");
	printArray(param.mp2Param.lambda, 20);
	printf("LambdaM: ");
	printArray(param.mp2Param.lambdaMultiplier, 20);
	printf("Ma: ");
	printArray(param.mp2Param.so2qGenerator.a, 20);
	printf("Mb: ");
	printArray(param.mp2Param.so2qGenerator.b, 20);
	printf("Mc: ");
	printArray(param.mp2Param.so2qGenerator.c, 20);
	printf("Md: ");
	printArray(param.mp2Param.so2qGenerator.d, 20);
}

*/



// ######################################

/**
 * Create Q_LENGTH random bytes and stores them in the array toFill
 * q: the cryptographic modulus q
 * toFill: array to store the Q_LENGTH random bytes. The value is allways less than the cryptographic modulus q
 */
 void fillRandomLessThanQ(unsigned char* q, unsigned char* toFill){
    unsigned char aux[8]; /* 8 is the number of bytes returned by the multos primitive */
    int t=8, i=0, r;

	/* WARNING: The simulator creates the same values many times!!!*/
    GetRandomNumber(aux);
    while(t<=Q_LENGTH)
    {
	   memcpy(&toFill[i], aux, 8);
		i+=8;
        t+=8;
        GetRandomNumber(aux);
    }
    r = Q_LENGTH - i;
    if (r != 0)
        memcpy(&toFill[i], aux, r);

 /* ModularReduction(OperandLength, ModulusLength, Operand, Modulus) */
    ModularReduction(Q_LENGTH, Q_LENGTH, toFill, q);
 }

/**
 * Create ALPHA_BITS_BYTE_LENGTH random bytes and stores them in the array toFill
 * It is assumed that ALPHA_BITS_BYTE_LENGTH is <= 8 bytes
 * toFill: array to store the random bytes.
 */
 void getRandomAlphaBits(unsigned char* toFill){
    unsigned char aux[8]; /* 8 is the number of bytes returned by the multos primitive */
    int i;
    //reset toFill value
    for(i = 0; i < ALPHA_BITS_BYTE_LENGTH; i++)
        toFill[i] = 0;
	
	GetRandomNumber(aux);
    memcpy(toFill, aux, ALPHA_BITS_BYTE_LENGTH);
 }

/**
 * Create a random value less than lambda and stores it in the array toFill.
 * It is assumed that LAMBDA_LENGTH = ALPHA_BITS_BYTE_LENGTH is <= 8 bytes
 * 
 * lambda: the MP2 lambda parameter. 
 * toFill: array to store the random bytes. The value is allways less than lambda.
 *
 */
 void getRandomLessThanLambda(unsigned char* lambda, unsigned char* toFill){
	getRandomAlphaBits(toFill);
	ModularReduction(LAMBDA_LENGTH, LAMBDA_LENGTH, toFill, lambda);
 }

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
 int compare (unsigned char* op1, unsigned char* op2, int length)
 {
    int i, r, v1, v2;
    for (i = 0; i < length; i++)
    {
        v1 = op1[i];
        v2 = op2[i];
        if(v1 > v2)
        {
            //printf("%02x - %02x : 1\n\n", v1, v2);
            return 1;
        }
        if(v1 < v2)
        {
            //printf("%02x - %02x : -1\n\n", v1, v2);
            return -1;
        }
    }
    return 0;
 }

/**
 * Verify if length bytes are zero.
 * return 1 of length bytes starting at v are zero; return 0 otherwise
 */
int isZero(unsigned char* v, int length)
{
    while(length > 0 )
    {
        length--;
        if(v[length] != 0) return 0;
    }
    return 1;
}




 /**
 * Perform subtraction modulus mod
 * res = op1 - op2 modulos mod
 * assumes that res, op1, op2 and mod have length = Q_LENGTH
 */
//necessary for Q of 512 bits
//#pragma melstatic


void subModQ(unsigned char* res, unsigned char* op1, unsigned char* op2, unsigned char* mod)
{
    unsigned char resAux[Q_LENGTH + 1];
    unsigned char op1Aux[Q_LENGTH + 1];
    unsigned char op2Aux[Q_LENGTH + 1];
	unsigned char op3Aux[Q_LENGTH + 1];
    unsigned char modAux[Q_LENGTH + 1];

    op1Aux[0] = 0;
    memcpy(&op1Aux[1], op1, Q_LENGTH);
    op2Aux[0] = 0;
    memcpy(&op2Aux[1], op2, Q_LENGTH);
    modAux[0] = 0;
    memcpy(&modAux[1], mod, Q_LENGTH);


    /* test if op1 < op2 */
    if(compare(op1, op2, Q_LENGTH) < 0)
    {
        ADDN(Q_LENGTH + 1, op3Aux, op1Aux, modAux);
        SUBN(Q_LENGTH + 1, resAux, op3Aux, op2Aux);
    } else {
        /* op1 > op2 */
        SUBN(Q_LENGTH + 1, resAux, op1Aux, op2Aux);
    }

    memcpy(res, &resAux[1], Q_LENGTH);
}


 /**
 * Perform subtraction modulus mod
 * res = op1 - op2 modulos mod
 * assumes that res, op1, op2 and mod have length = LAMBDA_LENGTH
 */
void subModLambda(unsigned char* res, unsigned char* op1, unsigned char* op2, unsigned char* mod)
{
    unsigned char resAux[LAMBDA_LENGTH + 1];
    unsigned char op1Aux[LAMBDA_LENGTH + 1];
    unsigned char op2Aux[LAMBDA_LENGTH + 1];
    unsigned char op3Aux[LAMBDA_LENGTH + 1];
    unsigned char modAux[LAMBDA_LENGTH + 1];

    op1Aux[0] = 0;
    memcpy(&op1Aux[1], op1, LAMBDA_LENGTH);
    op2Aux[0] = 0;
    memcpy(&op2Aux[1], op2, LAMBDA_LENGTH);
    modAux[0] = 0;
    memcpy(&modAux[1], mod, LAMBDA_LENGTH);


    /* test if op1 < op2 */
    if(compare(op1, op2, LAMBDA_LENGTH) < 0)
    {
        ADDN(LAMBDA_LENGTH + 1, op3Aux, op1Aux, modAux);
        SUBN(LAMBDA_LENGTH + 1, resAux, op3Aux, op2Aux);
    } else {
        /* op1 > op2 */
        SUBN(LAMBDA_LENGTH + 1, resAux, op1Aux, op2Aux);
    }

    memcpy(res, &resAux[1], LAMBDA_LENGTH);
}



/******************************************************************/
/** Matrix multiplication SO(2,q)**/
/******************************************************************/
void matrixModMultSO2Q(Matrix* ma, Matrix* mb, Matrix* mr, unsigned char* modulus)
{

    unsigned char t1[Q_LENGTH+1];
    unsigned char t2[Q_LENGTH+1];
    unsigned char t3[Q_LENGTH+1];
	
	/*printf("-Mult A--------------------\n");
    printArray(ma->a,20);
    printArray(ma->b,20);
    printArray(ma->c,20);
    printArray(ma->d,20);
    printf("-MULT B --------------------\n");
    printArray(mb->a,20);
    printArray(mb->b,20);
    printArray(mb->c,20);
    printArray(mb->d,20);
    printf("---------------------\n");*/


	/** mr.a */
	t1[0] = 0;
	t3[0] = 0;
	
	memcpy(&t1[1], ma->a, Q_LENGTH);
	memcpy(&t3[1], ma->b, Q_LENGTH);

	ModularMultiplication(Q_LENGTH, &t1[1], mb->a, modulus);
	ModularMultiplication(Q_LENGTH, &t3[1], mb->c, modulus);
	ADDN(Q_LENGTH+1, t2, t1, t3);
	ModularReduction(Q_LENGTH+1, Q_LENGTH, t2, modulus);
	memcpy(mr->a, &t2[1], Q_LENGTH);

	/** mr.d */
	memcpy(mr->d, &t2[1], Q_LENGTH);


	/** mr.b */
	
	t1[0] = 0;
	t3[0] = 0;
	memcpy(&t1[1], ma->a, Q_LENGTH);
	memcpy(&t3[1], ma->b, Q_LENGTH);
	

	ModularMultiplication(Q_LENGTH, &t1[1], mb->b, modulus);
	ModularMultiplication(Q_LENGTH, &t3[1], mb->d, modulus);
	ADDN(Q_LENGTH+1, t2, t1, t3);
	ModularReduction(Q_LENGTH+1, Q_LENGTH, t2, modulus);
	memcpy(mr->b, &t2[1], Q_LENGTH);

	/** mr.c */
	SUBN(Q_LENGTH, &t1[1], modulus, &t2[1]);
	memcpy(mr->c, &t1[1], Q_LENGTH);

	/*printf("-MULT R --------------------\n");
    printArray(mr->a,20);
    printArray(mr->b,20);
    printArray(mr->c,20);
    printArray(mr->d,20);
    printf("---------------------\n");*/
}






/******************************************************************
 * Matrix 2x2 in Z_q exponentiation by squaring
 *
 * Assumes: length of values in matrix,result,exponent and mudulus = Q_LENGTH
 * IMPORTANT NOTE: it uses the global matrices mA, mR and mAux in the computations
/******************************************************************/
void matrixModPowBySquaring(Matrix* matrix, Matrix* result, unsigned char* exponent, unsigned char* modulus)
{
	Matrix* temp;
	Matrix* ma;
	Matrix* mr;
	Matrix* aux;

    int i;
	
    unsigned char e[Q_LENGTH];	
	memcpy(e, exponent, Q_LENGTH);
	
	ma = &mA;
	mr = &mR;
	aux = &mAux;
/*
    for(i=0; i<Q_LENGTH-1; i++)
    {
        mr->a[i] = 0;
        mr->b[i] = 0;
        mr->c[i] = 0;
        mr->d[i] = 0;
    }
*/
	

    memcpy(ma->a, matrix->a, Q_LENGTH);
    memcpy(ma->b, matrix->b, Q_LENGTH);
    memcpy(ma->c, matrix->c, Q_LENGTH);
    memcpy(ma->d, matrix->d, Q_LENGTH);
			
	//é so fazer cópia do ma
	if ((e[Q_LENGTH - 1] & 0x01) == 1)
	{/*
		matrixModMultSO2Q(ma, mr, aux, modulus);
		//swap mr with aux
		temp = mr;
		mr = aux;
		aux = temp;
		*/
		memcpy(mr->a, matrix->a, Q_LENGTH);
		memcpy(mr->b, matrix->b, Q_LENGTH);
		memcpy(mr->c, matrix->c, Q_LENGTH);
		memcpy(mr->d, matrix->d, Q_LENGTH);
	
	}
	else
	{
		CLEARN(Q_LENGTH, mR.a);
		CLEARN(Q_LENGTH, mR.b);
		CLEARN(Q_LENGTH, mR.c);
		CLEARN(Q_LENGTH, mR.d);

		mr->a[Q_LENGTH-1] = 1;
		mr->b[Q_LENGTH-1] = 0;
		mr->c[Q_LENGTH-1] = 0;
		mr->d[Q_LENGTH-1] = 1;
	}
	ASSIGN_SHRN(Q_LENGTH, e, 1);

	while(isZero(e, Q_LENGTH) == 0)
	{
		matrixModMultSO2Q(ma, ma, aux, modulus);
		//swap ma with aux
		temp = ma;
		ma = aux;
		aux = temp;


        if ((e[Q_LENGTH - 1] & 0x01) == 1)
        {
			matrixModMultSO2Q(ma, mr, aux, modulus);
            //swap mr with aux
			temp = mr;
			mr = aux;
			aux = temp;
        }

        ASSIGN_SHRN(Q_LENGTH, e, 1);
    }


	if(mr != result)
	{
		memcpy(result->a, mr->a, Q_LENGTH);
		memcpy(result->b, mr->b, Q_LENGTH);
		memcpy(result->c, mr->c, Q_LENGTH);
		memcpy(result->d, mr->d, Q_LENGTH);
	}

	/*printf("-R--------------------\n");
	printArray(mr->a,20);
	printArray(mr->b,20);
	printArray(mr->c,20);
	printArray(mr->d,20);
	printf("---------------------\n");*/
}



