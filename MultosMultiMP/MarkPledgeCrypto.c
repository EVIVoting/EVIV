#include <string.h>
#include <stdio.h>

#include <multoscrypto.h>
#include <multosarith.h>
#include "MarkPledgeCrypto.h"
#include "MarkPledgeConstants.h"
#include "DataStructures.h"
#include "Util.h"


extern Matrix mR;

/**
 * Create the exponential ElGamal encryption of message m.
 INPUT
 *  kpub: public key
 *  m: message to encrypt
 *  r: random factor to encrypt m.
 *
 OUTPUT
 * result = <g^r>, <h^r . mpG^m> mod p
 *
 */
void exponentialElGamalEncryption(ExponentialElGamalPublicKey* kpub, unsigned char* m,
                                  unsigned char* r, ElGamalEncryption* result){
/* ModularExponentiation(ExponentLength, ModulusLength, Exponent, Modulus, Base, Result) */
/* ModularMultiplication(ModulusLength, Result, A, Modulus) -- outputs result = result * A mod Modulus

    /* step 1 - calculus of result->y =  h^r . mp3G^m  mod p*/
    /* step 1.1 - calculus of h^r  mod p*/
    ModularExponentiation(Q_LENGTH, P_LENGTH, r, kpub->p, kpub->h, result->y);
    /* step 1.2 - calculus of mp3G^m  mod p*/
    ModularExponentiation(Q_LENGTH, P_LENGTH, m, kpub->p, kpub->mpG, result->x);
    /* step 1.3 - calculus of result->y =  h^r . mpG^m  mod p*/
    ModularMultiplication(P_LENGTH, result->y, result->x, kpub->p);

    /* step 2 - calculus of result->x =  g^r  mod p*/
    ModularExponentiation(Q_LENGTH, P_LENGTH, r, kpub->p, kpub->g, result->x);
}

/**##############################################################
 *		Special ElGamalEncryptions								
 * ##############################################################*/


/**
 * Create the exponential ElGamal encryption of message m = 1.
 INPUT
 *  kpub: public key
 *  r: random factor to encrypt m.
 *
 OUTPUT
 * result = <g^r>, <h^r . mpG> mod p
 *
 */
void exponentialElGamalEncryptionMPG(ExponentialElGamalPublicKey* kpub,
                                  unsigned char* r, ElGamalEncryption* result){
/* ModularExponentiation(ExponentLength, ModulusLength, Exponent, Modulus, Base, Result) */
/* ModularMultiplication(ModulusLength, Result, A, Modulus) -- outputs result = result * A mod Modulus

    /* step 1 - calculus of result->y =  h^r . mpG mod p*/
    /* step 1.1 - calculus of h^r mod p*/
    ModularExponentiation(Q_LENGTH, P_LENGTH, r, kpub->p, kpub->h, result->y);
    /* step 1.2 - calculus of result->y =  h^r . mpG  mod p*/
	ModularMultiplication(P_LENGTH, result->y, kpub->mpG, kpub->p);
    /* step 2 - calculus of result->x =  g^r mod p*/
    ModularExponentiation(Q_LENGTH, P_LENGTH, r, kpub->p, kpub->g, result->x);
}


/**
 * Create the exponential ElGamal encryption of message m = -1.
 INPUT
 *  kpub: public key
 *  r: random factor to encrypt m.
 *
 OUTPUT
 * result = <g^r>, <h^r . mpGInv> mod p
 *
 */
void exponentialElGamalEncryptionMPGInv(ExponentialElGamalPublicKey* kpub,
                                  unsigned char* r, ElGamalEncryption* result){
/* ModularExponentiation(ExponentLength, ModulusLength, Exponent, Modulus, Base, Result) */
/* ModularMultiplication(ModulusLength, Result, A, Modulus) -- outputs result = result * A mod Modulus

    /* step 1 - calculus of result->y =  h^r . mpGInv mod p */
    /* step 1.1 - calculus of h^r mod p*/
    ModularExponentiation(Q_LENGTH, P_LENGTH, r, kpub->p, kpub->h, result->y);
    /* step 1.2 - calculus of result->y =  h^r . mpGInv mod p */
    ModularMultiplication(P_LENGTH, result->y, kpub->mpGInv, kpub->p);
    /* step 2 - calculus of result->x =  g^r mod p*/
    ModularExponentiation(Q_LENGTH, P_LENGTH, r, kpub->p, kpub->g, result->x);
}


/**
 * Compute the challenge for the CGS97 proof by hashing the BE, A1, A2, B1 and B2 values.
 */
void computeCGC97Challenge(unsigned char* c, unsigned char* digestData, unsigned char* q)
{
	unsigned char bc, bq;
	unsigned char auxHash[HASH_LENGTH];
	unsigned char cIndex = 0;
	unsigned char auxIndex = 0;


	/* auxHash = hash(x||y||a1||a2||b1||b2) */
    SHA1(P_LENGTH * 6, auxHash, digestData);

	while(cIndex < Q_LENGTH && auxIndex < HASH_LENGTH)
	{
		c[cIndex++] = auxHash[auxIndex++];
	}

	while(cIndex < Q_LENGTH)
	{
		SHA1(HASH_LENGTH, auxHash, auxHash);
		auxIndex = 0;
		while(cIndex < Q_LENGTH && auxIndex < HASH_LENGTH)
		{
			c[cIndex++] = auxHash[auxIndex++];
		}
	}


	/*adjust the result to Z_q by shifting the high order byte bits of 'c' until a value less than q is achieved*/ 
	bc = c[0];
	bq = q[0];
	while(bc > bq)
		bc >>= 1;
	c[0] = bc;
    
	//TODO: compute Q_LENGTH challenge

	/*
	printf("c:");
	printArray(c, 20);
	printArray(digestData, 20);
	printArray(&digestData[128], 20);
	printArray(&digestData[256], 20);
	printArray(&digestData[384], 20);
	printArray(&digestData[512], 20);
	printArray(&digestData[640], 20);
	*/
}

/**
 * Create the CGS97 ballot validity proof.
 INPUT
 * cryptParam: public cryptographic parameters
 * alpha: the random value used in the proof->be bit encryption
 * proof->be: the bit encryption
 * isYesVote: flag that indicates if the proof is for a YESvote (value 1) or for a NOvote (value 0)
 *
 OUTPUT
 * the CGS97 proof stored in the corresponding p entries.
 */
//necessary for Q of 512 bits
//#pragma melstatic

void createCGS97Proof(ExponentialElGamalPublicKey* cryptoParam, unsigned char* alpha, CGS97Proof* proof, int isYesVote){
/* ModularExponentiation(ExponentLength, ModulusLength, Exponent, Modulus, Base, Result) */
/* ModularMultiplication(ModulusLength, Result, A, Modulus) -- outputs result = result * A mod Modulus
/* ModularReduction(OperandLength, ModulusLength, Operand, Modulus) */

    /* aux1 and aux2 are auxiliary variables to perform some required modular functions */
    unsigned char aux1[Q_LENGTH + 1];
    unsigned char aux2[Q_LENGTH + 1];
    unsigned char res[Q_LENGTH + 1];
	unsigned char w[Q_LENGTH];


    fillRandomLessThanQ(cryptoParam->q, w);


    /* YESvote */
    if(isYesVote == 1){
        /* r1 */
        fillRandomLessThanQ(cryptoParam->q, proof->r1);

        /* d1 */
        fillRandomLessThanQ(cryptoParam->q, proof->d1);

        /* a1  = g^r1.x^d1 mod p*/
        ModularExponentiation(Q_LENGTH, P_LENGTH, proof->r1, cryptoParam->p, cryptoParam->g, proof->a1); /*a1 = g^r1*/
		ModularExponentiation(Q_LENGTH, P_LENGTH, proof->d1, cryptoParam->p, proof->canonicalVote.x, proof->a2); /* a2 = x^d1 */
        ModularMultiplication(P_LENGTH, proof->a1, proof->a2, cryptoParam->p); /* a1 = a1.a2 = g^r1.x^d1*/

        /* b1 = h^r1.(y.G)^d1 mod p*/
        ModularExponentiation(Q_LENGTH, P_LENGTH, proof->r1, cryptoParam->p, cryptoParam->h, proof->b1); /* b1 = h^r1 */
        memcpy(proof->b2, proof->canonicalVote.y, P_LENGTH); /* b2 = y */
        ModularMultiplication(P_LENGTH, proof->b2, cryptoParam->mpG, cryptoParam->p); /* b2 = b2.mp3G = y.mp3G */
        ModularExponentiation(Q_LENGTH, P_LENGTH, proof->d1, cryptoParam->p, proof->b2, proof->b2); /* b2 = b2^d1 = (y.mp3G)^d1 */
        ModularMultiplication(P_LENGTH, proof->b1, proof->b2, cryptoParam->p); /* b1 = b1.b2 = h^r1.(y.mp3G)^d1 */

        /* a2 = g^w mod p*/
        ModularExponentiation(Q_LENGTH, P_LENGTH, w, cryptoParam->p, cryptoParam->g, proof->a2); /*a2 = g^w*/

        /* b2 = h^w mod p*/
        ModularExponentiation(Q_LENGTH, P_LENGTH, w, cryptoParam->p, cryptoParam->h, proof->b2); /*b2 = h^w*/

        /* c = hash(x||y||a1||a2||b1||b2) */
        //SHA1(P_LENGTH * 6, proof->c, digestData);
		/*printf("CGS YES\n");*/
		computeCGC97Challenge(proof->c, (unsigned char*)proof, cryptoParam->q);
        
		subModQ(res, proof->c, proof->d1, cryptoParam->q);
        memcpy(proof->d2, res, Q_LENGTH); /* d2 = c - d1 mod q*/
		
        /* r2 = w - alpha.d2 mod q */
        aux1[0] = 0;
        memcpy(&aux1[1], w, Q_LENGTH); /* aux1 = w */
        aux2[0] = 0;
        memcpy(&aux2[1], alpha, Q_LENGTH); /* aux2 = alpha */
        ModularMultiplication(Q_LENGTH, &aux2[1], proof->d2, cryptoParam->q); /* aux2 = alpha.d2 */
        subModQ(&res[1], &aux1[1], &aux2[1], cryptoParam->q);
        memcpy(proof->r2, &res[1], Q_LENGTH); /* r2 = w - alpha.d2 mod q*/


    } else if(isYesVote == 0) {
    /* NOvote */
        /* r2 */
        fillRandomLessThanQ(cryptoParam->q, proof->r2);

        /* d2 */
        fillRandomLessThanQ(cryptoParam->q, proof->d2);


        /* a2  = g^r2.x^d2 mod p*/
        ModularExponentiation(Q_LENGTH, P_LENGTH, proof->r2, cryptoParam->p, cryptoParam->g, proof->a2); /*a2 = g^r2*/
        ModularExponentiation(Q_LENGTH, P_LENGTH, proof->d2, cryptoParam->p, proof->canonicalVote.x, proof->a1); /* a1 = x^d2 */
        ModularMultiplication(P_LENGTH, proof->a2, proof->a1, cryptoParam->p); /* a2 = a2.a1 = g^r2.x^d2 */

        /* b2 = h^r2.(y.G^-1)^d2 mod p*/
		ModularExponentiation(Q_LENGTH, P_LENGTH, proof->r2, cryptoParam->p, cryptoParam->h, proof->b2); /* b2 = h^r2 */
		memcpy(proof->b1, proof->canonicalVote.y, P_LENGTH); /* b1 = y */
		ModularMultiplication(P_LENGTH, proof->b1, cryptoParam->mpGInv, cryptoParam->p); /* b1 = b1.mp3GInv = y.mp3GInv */
        ModularExponentiation(Q_LENGTH, P_LENGTH, proof->d2, cryptoParam->p, proof->b1, proof->b1); /* b1 = b1^d2 = (y.mp3GInv)^d2 */
        ModularMultiplication(P_LENGTH, proof->b2, proof->b1, cryptoParam->p); /* b2 = b2.b1 = h^r2.(y.mp3GInv)^d2 */
		
        /* a1 = g^w mod p*/
        ModularExponentiation(Q_LENGTH, P_LENGTH, w, cryptoParam->p, cryptoParam->g, proof->a1); /*a1 = g^w*/

        /* b1 = h^w mod p*/
        ModularExponentiation(Q_LENGTH, P_LENGTH, w, cryptoParam->p, cryptoParam->h, proof->b1); /*b1 = h^w*/

        /* c = hash(x||y||a1||a2||b1||b2) */
        //printf("CGS NO\n");
        computeCGC97Challenge(proof->c, (unsigned char*)proof, cryptoParam->q);
		
		//printf("C: ");
		//printArray(proof->c, 20);
		
        subModQ(res, proof->c, proof->d2, cryptoParam->q);
		memcpy(proof->d1, res, Q_LENGTH); /* d1 = c - d2 mod q*/
		
        /* r1 = w - alpha.d1 mod q*/
        aux1[0] = 0;
        memcpy(&aux1[1], w, Q_LENGTH); /* aux1 = w */
        aux2[0] = 0;
        memcpy(&aux2[1], alpha, Q_LENGTH); /* aux2 = alpha */
        ModularMultiplication(Q_LENGTH, &aux2[1], proof->d1, cryptoParam->q); /* aux2 = alpha.d1 */
        subModQ(&res[1], &aux1[1], &aux2[1], cryptoParam->q);
        memcpy(proof->r1, &res[1], Q_LENGTH); /* r1 = w - alpha.d1 mod q*/

    }
	/*
	printf("CGS:\n");
	printArray(alpha,20);
	printArray(proof->canonicalVote.x,30);
	printArray(proof->canonicalVote.y,30);
	printArray(proof->a1,30);
	printArray(proof->a2,30);
	printArray(proof->b1,30);
	printArray(proof->b2,30);
	printArray(proof->r1,20);
	printArray(proof->r2,20);
	printArray(proof->d1,20);
	printArray(proof->d2,20);
	*/
}

/** Sum the canonical vote factors
INPUT
 * factors: the canonical vote encryption factors
 * numberOfCandidates: the number of candidates running in the election = number of canonical votes
 * modulusQ: the public key cryptographic modulus q
OUTPUT
 * fills the result array with the sum of the canonical vote factors
 */
 void createSumReceipt(CanonicalFactors* factors, unsigned char numberOfCandidates, 
	 unsigned char* result, unsigned char* modulusQ)
 {
/* ModularMultiplication(ModulusLength, Result, A, Modulus) -- outputs result = result * A mod Modulus
/* ModularReduction(OperandLength, ModulusLength, Operand, Modulus) */

    unsigned char aux[Q_LENGTH + 1];
    unsigned char res[Q_LENGTH + 1];
    int i;

    aux[0] = 0;
    res[0] = 0;
	memcpy(&res[1], factors->canonicalFactor[0], Q_LENGTH);

    for(i=1; i< numberOfCandidates; i++)
    {
		memcpy(&aux[1], factors->canonicalFactor[i], Q_LENGTH);
        ADDN(Q_LENGTH+1, res, res, aux); /* res += aux */
    }
    ModularReduction(Q_LENGTH + 1, Q_LENGTH, res, modulusQ); 
    memcpy(result, &res[1], Q_LENGTH);
}


/** ##################################################################
 *						MP1
 *  ##################################################################*/

 /* METHOD  *** NOT IN USE ***
  *	
  * TODO debug  
  * Method to create the MP1 and MP1A BMP encryptions
  */
void createBMPEncryptions(unsigned char* verificationCode, BMPEncryptionFactors** encryptionFactors, BMP** BMPEncryptions,
	MarkPledgeParameters* param, unsigned char isYesVote)
{
	unsigned char vCode[ALPHA_BITS_BYTE_LENGTH];
	unsigned char iBMP;
	unsigned char bit;
	
	memcpy(vCode, verificationCode, ALPHA_BITS_BYTE_LENGTH);
	
	
	if(isYesVote == 1)
	{
		printf("YES vote\n");
		/* create BMP vote encryptions */
		//for(iBMP = 0; iBMP<param->alpha; iBMP++)
		for(iBMP = 0; iBMP<2; iBMP++)
		{
			bit = vCode[0] & 0x80;
			ASSIGN_SHLN(ALPHA_BITS_BYTE_LENGTH, vCode, 1);

			if(bit != 0)
			{
				printf("Bit 1\n");
				exponentialElGamalEncryptionMPG(&param->kpub, encryptionFactors[iBMP]->left, &BMPEncryptions[iBMP]->left);
				exponentialElGamalEncryptionMPG(&param->kpub, encryptionFactors[iBMP]->right, &BMPEncryptions[iBMP]->right);
			}
			else
			{
				printf("Bit 0\n");
				exponentialElGamalEncryptionMPGInv(&param->kpub, encryptionFactors[iBMP]->left, &BMPEncryptions[iBMP]->left);
				exponentialElGamalEncryptionMPGInv(&param->kpub, encryptionFactors[iBMP]->right, &BMPEncryptions[iBMP]->right);
			}	
		}

	}
	else
	{
		printf("No vote\n");
		/* create BMP vote encryptions */
		//for(iBMP = 0; iBMP<param->alpha; iBMP++)
		for(iBMP = 0; iBMP<2; iBMP++)
		{
			bit = vCode[0] & 0x80;
			ASSIGN_SHLN(ALPHA_BITS_BYTE_LENGTH, vCode, 1);

			if(bit != 0)
			{
				printf("Bit 1\n");
				exponentialElGamalEncryptionMPG(&param->kpub, encryptionFactors[iBMP]->left, &BMPEncryptions[iBMP]->left);
				exponentialElGamalEncryptionMPGInv(&param->kpub, encryptionFactors[iBMP]->right, &BMPEncryptions[iBMP]->right);
			}
			else
			{
				printf("Bit 0\n");
				exponentialElGamalEncryptionMPGInv(&param->kpub, encryptionFactors[iBMP]->left, &BMPEncryptions[iBMP]->left);
				exponentialElGamalEncryptionMPG(&param->kpub, encryptionFactors[iBMP]->right, &BMPEncryptions[iBMP]->right);
			}	
	
		}
	}

}



 /** Prepare the ballot encryptionon, i.e. initial verification codes and encryption factors
INPUT
 * verificationCodes: initially it contains the values encrypted in ccode
 * encryptionFactors: vote encryption factors
 * param: MarkPledge parameters (includes public key)
 * numberOfcandidates: the number of candidates running in the election
OUTPUT
 * verificationCodes: initialized with the values encrypted in the candidate encryption
 * encryptionFactors: vote encryption factors
 */
void prepareBallotMP1(VerificationCodes* verificationCodes, EncryptionFactors* encryptionFactors, 
	MarkPledgeParameters* param, unsigned char numberOfCandidates)
{
	int i,k;
	for(i=0; i<numberOfCandidates; i++)
	{
		for(k=0; k<param->alpha; k++)
		{
			fillRandomLessThanQ(param->kpub.q, encryptionFactors->mp1EncryptionFactors[i].bmpFactor[k].left);
			fillRandomLessThanQ(param->kpub.q, encryptionFactors->mp1EncryptionFactors[i].bmpFactor[k].right);
		}
		getRandomAlphaBits(verificationCodes->verificationCode[i]);
	}
}

/** Create the vote encryption
INPUT
 * verificationCodes: initially it contains the values encrypted in ccode
 * encryptionFactors: vote encryption factors
 * param: MarkPledge parameters (includes public key)
 * isYesVote: 1 if the candidate encryption is for a yes vote and 0 otherwise
 * candidateIndex: the candidate encryption index
OUTPUT
 * voteEncryption: the vote encryption storage structure
 */
void createCandidateEncryptionMP1(VerificationCodes* verificationCodes, 
	EncryptionFactors* encryptionFactors, VoteEncryption* voteEncryption, 
	MarkPledgeParameters* param, unsigned char isYesVote, unsigned char candidateIndex)
{
	/*
	createBMPEncryptions(verificationCodes->verificationCode[candidateIndex],
		(BMPEncryptionFactors**)&encryptionFactors->mp1EncryptionFactors[candidateIndex].bmpFactor[0],
		(BMP**)&voteEncryption->voteEncryption.mp1.bmp[0], param, isYesVote);
	*/

	unsigned char vCode[ALPHA_BITS_BYTE_LENGTH];
	unsigned char iBMP;
	unsigned char bit;
	memcpy(vCode, verificationCodes->verificationCode[candidateIndex], ALPHA_BITS_BYTE_LENGTH);

	 
	if(isYesVote == 1)
	{

		/* create BMP vote encryptions */
		for(iBMP = 0; iBMP<param->alpha; iBMP++)
		{
			bit = vCode[0] & 0x80;
			ASSIGN_SHLN(ALPHA_BITS_BYTE_LENGTH, vCode, 1);

			if(bit != 0)
			{
				exponentialElGamalEncryptionMPG(&param->kpub,
					encryptionFactors->mp1EncryptionFactors[candidateIndex].bmpFactor[iBMP].left,
					&voteEncryption->voteEncryption.mp1.bmp[iBMP].left);

				exponentialElGamalEncryptionMPG(&param->kpub,
					encryptionFactors->mp1EncryptionFactors[candidateIndex].bmpFactor[iBMP].right,
					&voteEncryption->voteEncryption.mp1.bmp[iBMP].right);
			}
			else
			{
				exponentialElGamalEncryptionMPGInv(&param->kpub,
					encryptionFactors->mp1EncryptionFactors[candidateIndex].bmpFactor[iBMP].left,
					&voteEncryption->voteEncryption.mp1.bmp[iBMP].left);

				exponentialElGamalEncryptionMPGInv(&param->kpub,
					encryptionFactors->mp1EncryptionFactors[candidateIndex].bmpFactor[iBMP].right,
					&voteEncryption->voteEncryption.mp1.bmp[iBMP].right);
			}	
		}

	}
	else //NO vote
	{

		/* create BMP vote encryptions */
		for(iBMP = 0; iBMP<param->alpha; iBMP++)
		{
			bit = vCode[0] & 0x80;
			ASSIGN_SHLN(ALPHA_BITS_BYTE_LENGTH, vCode, 1);

			if(bit != 0)
			{
				exponentialElGamalEncryptionMPG(&param->kpub,
					encryptionFactors->mp1EncryptionFactors[candidateIndex].bmpFactor[iBMP].left,
					&voteEncryption->voteEncryption.mp1.bmp[iBMP].left);

				exponentialElGamalEncryptionMPGInv(&param->kpub,
					encryptionFactors->mp1EncryptionFactors[candidateIndex].bmpFactor[iBMP].right,
					&voteEncryption->voteEncryption.mp1.bmp[iBMP].right);
			}
			else
			{
				exponentialElGamalEncryptionMPGInv(&param->kpub,
					encryptionFactors->mp1EncryptionFactors[candidateIndex].bmpFactor[iBMP].left,
					&voteEncryption->voteEncryption.mp1.bmp[iBMP].left);

				exponentialElGamalEncryptionMPG(&param->kpub,
					encryptionFactors->mp1EncryptionFactors[candidateIndex].bmpFactor[iBMP].right,
					&voteEncryption->voteEncryption.mp1.bmp[iBMP].right);
			}	
		}
	}
}



 /** Create the vote receipt, i.e. vcode and vcodeFactor values
INPUT
 * verificationCodes: initially it contains the values encrypted in ccode
 * encryptionFactors: vote encryption factors
 * param: MarkPledge parameters (includes public key)
 * challenge: the challenge to the vote
 * yesVotePosition: position of the yes vote
 * numberOfCandidates: numberOfCandidates running in the election
OUTPUT
 * verificationCodes: filled with the final verification codes
 * encryptionFactors: filled with the validity factors on the left BMP elements
 */
 void createReceiptMP1(VerificationCodes* verificationCodes, EncryptionFactors* encryptionFactors,
	 MarkPledgeParameters* param,	 unsigned char* challenge, unsigned char yesVotePosition,
	 unsigned char numberOfCandidates)
 {
	unsigned char vCode[ALPHA_BITS_BYTE_LENGTH];
	unsigned char notVCode[ALPHA_BITS_BYTE_LENGTH];
	unsigned char chal[ALPHA_BITS_BYTE_LENGTH];
	unsigned char notChal[ALPHA_BITS_BYTE_LENGTH];
	unsigned char aux1[ALPHA_BITS_BYTE_LENGTH];
	unsigned char aux2[ALPHA_BITS_BYTE_LENGTH];
	unsigned char res[ALPHA_BITS_BYTE_LENGTH];
	
	unsigned char iCandidate;
	unsigned char iBMP;
	unsigned char bitVCode;
	unsigned char bitChal;

	
	memcpy(notChal, challenge, ALPHA_BITS_BYTE_LENGTH);
	NOTN(ALPHA_BITS_BYTE_LENGTH, notChal);
	
	for(iCandidate = 0; iCandidate < numberOfCandidates; iCandidate++)
	{
		memcpy(vCode, verificationCodes->verificationCode[iCandidate], ALPHA_BITS_BYTE_LENGTH);
		memcpy(chal, challenge, ALPHA_BITS_BYTE_LENGTH);	
		
		if(iCandidate != yesVotePosition)
		{
			memcpy(notVCode, verificationCodes->verificationCode[iCandidate], ALPHA_BITS_BYTE_LENGTH);
			NOTN(ALPHA_BITS_BYTE_LENGTH, notVCode);
			ANDN(ALPHA_BITS_BYTE_LENGTH,aux1,vCode,notChal);
			ANDN(ALPHA_BITS_BYTE_LENGTH,aux2,notVCode,chal);

			/*assign final vcode*/
			ORN(ALPHA_BITS_BYTE_LENGTH, res, aux1, aux2); 
			memcpy(verificationCodes->verificationCode[iCandidate], res, ALPHA_BITS_BYTE_LENGTH);
		}

		/* for each BMP */
		for(iBMP = 0; iBMP<param->alpha; iBMP++)
		{
			bitChal = chal[0] & 0x80;
			ASSIGN_SHLN(ALPHA_BITS_BYTE_LENGTH, chal, 1);

			if(bitChal != 0) // open right BMP element
			{
				memcpy(encryptionFactors->mp1EncryptionFactors[iCandidate].bmpFactor[iBMP].left,
					encryptionFactors->mp1EncryptionFactors[iCandidate].bmpFactor[iBMP].right, Q_LENGTH);
			}	
		}

	}
 }




/** ##################################################################
  *						MP1A 
  *  ##################################################################*/

/** Prepare the ballot encryptionon, i.e. initial verification codes and encryption factors
INPUT
 * verificationCodes: initially it contains the values encrypted in ccode
 * encryptionFactors: vote encryption factors
 * param: MarkPledge parameters (includes public key)
 * numberOfcandidates: the number of candidates running in the election
OUTPUT
 * verificationCodes: initialized with the values encrypted in the candidate encryption
 * encryptionFactors: vote encryption factors
 */
void prepareBallotMP1A(VerificationCodes* verificationCodes, EncryptionFactors* encryptionFactors, 
	MarkPledgeParameters* param, unsigned char numberOfCandidates)
{
	int i,k;
	for(i=0; i<numberOfCandidates; i++)
	{
		for(k=0; k<param->alpha; k++)
		{
			fillRandomLessThanQ(param->kpub.q, encryptionFactors->mp1AEncryptionFactors[i].bmpFactor[k].left);
			fillRandomLessThanQ(param->kpub.q, encryptionFactors->mp1AEncryptionFactors[i].bmpFactor[k].right);
		}
		fillRandomLessThanQ(param->kpub.q, encryptionFactors->mp1AEncryptionFactors[i].canonicalVoteFactor);
		getRandomAlphaBits(verificationCodes->verificationCode[i]);
	}
}

/** Create the vote encryption
INPUT
 * verificationCodes: initially it contains the values encrypted in ccode
 * encryptionFactors: vote encryption factors
 * param: MarkPledge parameters (includes public key)
 * isYesVote: 1 if the candidate encryption is for a yes vote and 0 otherwise
 * candidateIndex: the candidate encryption index
OUTPUT
 * voteEncryption: the vote encryption storage structure
 */
void createCandidateEncryptionMP1A(VerificationCodes* verificationCodes, 
	EncryptionFactors* encryptionFactors, VoteEncryption* voteEncryption, 
	MarkPledgeParameters* param, unsigned char isYesVote, unsigned char candidateIndex)
{
	unsigned char vCode[ALPHA_BITS_BYTE_LENGTH];
	unsigned char iBMP;
	unsigned char bit;
	memcpy(vCode, verificationCodes->verificationCode[candidateIndex], ALPHA_BITS_BYTE_LENGTH);

	 
	if(isYesVote == 1)
	{
		/* create canonical vote encryption */
		exponentialElGamalEncryptionMPG(&param->kpub,
			encryptionFactors->mp1AEncryptionFactors[candidateIndex].canonicalVoteFactor,
			&voteEncryption->voteEncryption.mp1A.canonicalVote);

		/* create BMP vote encryptions */
		for(iBMP = 0; iBMP<param->alpha; iBMP++)
		{
			bit = vCode[0] & 0x80;
			ASSIGN_SHLN(ALPHA_BITS_BYTE_LENGTH, vCode, 1);

			if(bit != 0)
			{
				exponentialElGamalEncryptionMPG(&param->kpub,
					encryptionFactors->mp1AEncryptionFactors[candidateIndex].bmpFactor[iBMP].left,
					&voteEncryption->voteEncryption.mp1A.bmp[iBMP].left);

				exponentialElGamalEncryptionMPG(&param->kpub,
					encryptionFactors->mp1AEncryptionFactors[candidateIndex].bmpFactor[iBMP].right,
					&voteEncryption->voteEncryption.mp1A.bmp[iBMP].right);
			}
			else
			{
				exponentialElGamalEncryptionMPGInv(&param->kpub,
					encryptionFactors->mp1AEncryptionFactors[candidateIndex].bmpFactor[iBMP].left,
					&voteEncryption->voteEncryption.mp1A.bmp[iBMP].left);

				exponentialElGamalEncryptionMPGInv(&param->kpub,
					encryptionFactors->mp1AEncryptionFactors[candidateIndex].bmpFactor[iBMP].right,
					&voteEncryption->voteEncryption.mp1A.bmp[iBMP].right);
			}	
		}

	}
	else
	{
		/* create canonical vote encryption */
		exponentialElGamalEncryptionMPGInv(&param->kpub,
			encryptionFactors->mp1AEncryptionFactors[candidateIndex].canonicalVoteFactor,
			&voteEncryption->voteEncryption.mp1A.canonicalVote);

		/* create BMP vote encryptions */
		for(iBMP = 0; iBMP<param->alpha; iBMP++)
		{
			bit = vCode[0] & 0x80;
			ASSIGN_SHLN(ALPHA_BITS_BYTE_LENGTH, vCode, 1);

			if(bit != 0)
			{
				exponentialElGamalEncryptionMPG(&param->kpub,
					encryptionFactors->mp1AEncryptionFactors[candidateIndex].bmpFactor[iBMP].left,
					&voteEncryption->voteEncryption.mp1A.bmp[iBMP].left);

				exponentialElGamalEncryptionMPGInv(&param->kpub,
					encryptionFactors->mp1AEncryptionFactors[candidateIndex].bmpFactor[iBMP].right,
					&voteEncryption->voteEncryption.mp1A.bmp[iBMP].right);
			}
			else
			{
				exponentialElGamalEncryptionMPGInv(&param->kpub,
					encryptionFactors->mp1AEncryptionFactors[candidateIndex].bmpFactor[iBMP].left,
					&voteEncryption->voteEncryption.mp1A.bmp[iBMP].left);

				exponentialElGamalEncryptionMPG(&param->kpub,
					encryptionFactors->mp1AEncryptionFactors[candidateIndex].bmpFactor[iBMP].right,
					&voteEncryption->voteEncryption.mp1A.bmp[iBMP].right);
			}	
		}
	}
	/*
	createBMPEncryptions(verificationCodes->verificationCode[candidateIndex],
		(BMPEncryptionFactors**)&encryptionFactors->mp1AEncryptionFactors[candidateIndex].bmpFactor,
		(BMP**)&voteEncryption->voteEncryption.mp1A.bmp, param, isYesVote);
	*/
}

 /** Create the vote receipt, i.e. vcode and vcodeFactor values
INPUT
 * verificationCodes: initially it contains the values encrypted in ccode
 * encryptionFactors: vote encryption factors
 * param: MarkPledge parameters (includes public key)
 * challenge: the challenge to the vote
 * yesVotePosition: position of the yes vote
 * numberOfCandidates: numberOfCandidates running in the election
OUTPUT
 * verificationCodes: filled with the final verification codes
 * encryptionFactors: filled with the validity factors
 */
 void createReceiptMP1A(VerificationCodes* verificationCodes, EncryptionFactors* encryptionFactors,
	 MarkPledgeParameters* param,	 unsigned char* challenge, unsigned char yesVotePosition,
	 unsigned char numberOfCandidates)
 {
 	unsigned char vCode[ALPHA_BITS_BYTE_LENGTH];
	unsigned char notVCode[ALPHA_BITS_BYTE_LENGTH];
	unsigned char chal[ALPHA_BITS_BYTE_LENGTH];
	unsigned char notChal[ALPHA_BITS_BYTE_LENGTH];
	unsigned char aux1[ALPHA_BITS_BYTE_LENGTH];
	unsigned char aux2[ALPHA_BITS_BYTE_LENGTH];
	unsigned char iCandidate;
	unsigned char iBMP;
	unsigned char bitVCode;
	unsigned char bitChal;

	/*
	 * auxiliary variables to compute the comformity factor
	 */
	unsigned char res[Q_LENGTH + 1];
    unsigned char op1[Q_LENGTH + 1];
    unsigned char op2[Q_LENGTH + 1];
	op1[0]=0;
	op2[0]=0;


	memcpy(vCode, verificationCodes->verificationCode[iCandidate], ALPHA_BITS_BYTE_LENGTH);
	memcpy(chal, challenge, ALPHA_BITS_BYTE_LENGTH);

	for(iCandidate = 0; iCandidate < numberOfCandidates; iCandidate++)
	{
		memcpy(vCode, verificationCodes->verificationCode[iCandidate], ALPHA_BITS_BYTE_LENGTH);
		memcpy(chal, challenge, ALPHA_BITS_BYTE_LENGTH);
		
		if(iCandidate != yesVotePosition)
		{
			memcpy(notVCode, verificationCodes->verificationCode[iCandidate], ALPHA_BITS_BYTE_LENGTH);
			memcpy(notChal, challenge, ALPHA_BITS_BYTE_LENGTH);
			NOTN(ALPHA_BITS_BYTE_LENGTH, notVCode);
			NOTN(ALPHA_BITS_BYTE_LENGTH, notChal);
			ANDN(ALPHA_BITS_BYTE_LENGTH,aux1,vCode,notChal);
			ANDN(ALPHA_BITS_BYTE_LENGTH,aux2,notVCode,chal);

			/*assign final vcode*/
			ORN(ALPHA_BITS_BYTE_LENGTH, vCode, aux1, aux2); 
			memcpy(verificationCodes->verificationCode[iCandidate], vCode, ALPHA_BITS_BYTE_LENGTH);
		}
		//prepare confirmity factor computation
		memcpy(&op1[1], encryptionFactors->mp1AEncryptionFactors[iCandidate].canonicalVoteFactor, Q_LENGTH);
		
		/* for each BMP */
		for(iBMP = 0; iBMP<param->alpha; iBMP++)
		{
			//TODO create conformity factor
			bitChal = chal[0] & 0x80;
			ASSIGN_SHLN(ALPHA_BITS_BYTE_LENGTH, chal, 1);
			bitVCode = vCode[0] & 0x80;
			ASSIGN_SHLN(ALPHA_BITS_BYTE_LENGTH, vCode, 1);

			if(bitChal != 0) // open right BMP element
			{
				//compute the conformity factor
				// using left encryption factor (the unopen bit) for the conformity factor calculus
				memcpy(&op2[1], encryptionFactors->mp1AEncryptionFactors[iCandidate].bmpFactor[iBMP].left, Q_LENGTH);
				
				//copy revealed BMP element encryption factor
				// reveal right element encryption factor, i.e. copy to the left position
				memcpy(encryptionFactors->mp1AEncryptionFactors[iCandidate].bmpFactor[iBMP].left,
					encryptionFactors->mp1AEncryptionFactors[iCandidate].bmpFactor[iBMP].right, Q_LENGTH);
			}	
			else
			{ //open left element
			  // to reveal encryption factor already on the left side 

				// using right encryption factor (the unopen bit) for the conformity factor calculus
				memcpy(&op2[1], encryptionFactors->mp1AEncryptionFactors[iCandidate].bmpFactor[iBMP].right, Q_LENGTH);
			}

			//test revealed bit
			if(bitVCode == 0)
			{//sum encryption factors
				ADDN(Q_LENGTH+1,res,op1,op2);
				ModularReduction(Q_LENGTH+1, Q_LENGTH, res, param->kpub.q);
			}
			else
			{ //subtract encryption factors
				subModQ(&res[1], &op1[1], &op2[1], param->kpub.q);
			}

			//copy conformity factor
			memcpy(encryptionFactors->mp1AEncryptionFactors[iCandidate].bmpFactor[iBMP].right, &res[1], Q_LENGTH);
		}

	}
 }


 /** ##################################################################
  *						MP2
  *  ##################################################################*/

/** Prepare the ballot encryptionon, i.e. initial verification codes and encryption factors
INPUT
 * verificationCodes: initially it contains the values encrypted in ccode
 * encryptionFactors: vote encryption factors
 * param: MarkPledge parameters (includes public key)
 * numberOfcandidates: the number of candidates running in the election
OUTPUT
 * verificationCodes: initialized with the values encrypted in the candidate encryption
 * encryptionFactors: vote encryption factors
 */
void prepareBallotMP2(VerificationCodes* verificationCodes, EncryptionFactors* encryptionFactors, 
	MarkPledgeParameters* param, unsigned char numberOfCandidates)
{
	int i;
	for(i=0; i<numberOfCandidates; i++)
	{
		fillRandomLessThanQ(param->kpub.q, encryptionFactors->mp2EncryptionFactors[i].vectorComponentX);
		fillRandomLessThanQ(param->kpub.q, encryptionFactors->mp2EncryptionFactors[i].vectorComponentY);
		getRandomLessThanLambda(param->mp2Param.lambda, verificationCodes->verificationCode[i]);
	}
}

/** Create the vote encryption
INPUT
 * verificationCodes: initially it contains the values encrypted in ccode
 * encryptionFactors: vote encryption factors
 * param: MarkPledge parameters (includes public key)
 * isYesVote: 1 if the candidate encryption is for a yes vote and 0 otherwise
 * candidateIndex: the candidate encryption index
OUTPUT
 * voteEncryption: the vote encryption storage structure
 */
void createCandidateEncryptionMP2(VerificationCodes* verificationCodes, 
	EncryptionFactors* encryptionFactors, VoteEncryption* voteEncryption, 
	MarkPledgeParameters* param, unsigned char isYesVote, unsigned char candidateIndex)
{
	unsigned char exponent[Q_LENGTH];
		
	transformToExponent(isYesVote, exponent, verificationCodes->verificationCode[candidateIndex], 
		param->mp2Param.lambdaMultiplier, param->kpub.q);
	
	matrixModPowBySquaring(&(param->mp2Param.so2qGenerator), &mR, exponent, param->kpub.q);
		
	/* encrypt vector x component */
	exponentialElGamalEncryption(&param->kpub, mR.a,
		encryptionFactors->mp2EncryptionFactors[candidateIndex].vectorComponentX,
		&voteEncryption->voteEncryption.mp2.candidateEncryption.vectorComponentX);

	/* encrypt vector y component */
	exponentialElGamalEncryption(&param->kpub, mR.b,
		encryptionFactors->mp2EncryptionFactors[candidateIndex].vectorComponentY,
		&voteEncryption->voteEncryption.mp2.candidateEncryption.vectorComponentY);

	/*copy to "presistent" storage in order to allow the later canonical vote construction*/
	memcpy(&voteEncryption->voteEncryption.mp2.tempCandidateEncryption[candidateIndex].vectorComponentX.x,
		&voteEncryption->voteEncryption.mp2.candidateEncryption.vectorComponentX.x, P_LENGTH);

	memcpy(&voteEncryption->voteEncryption.mp2.tempCandidateEncryption[candidateIndex].vectorComponentX.y,
		&voteEncryption->voteEncryption.mp2.candidateEncryption.vectorComponentX.y, P_LENGTH);

	memcpy(&voteEncryption->voteEncryption.mp2.tempCandidateEncryption[candidateIndex].vectorComponentY.x,
		&voteEncryption->voteEncryption.mp2.candidateEncryption.vectorComponentY.x, P_LENGTH);

	memcpy(&voteEncryption->voteEncryption.mp2.tempCandidateEncryption[candidateIndex].vectorComponentY.y,
		&voteEncryption->voteEncryption.mp2.candidateEncryption.vectorComponentY.y, P_LENGTH);

	}


 /** Create the vote receipt, i.e. vcode and vcodeFactor values
INPUT
 * verificationCodes: initially it contains the values encrypted in ccode
 * encryptionFactors: vote encryption factors
 * param: MarkPledge parameters (includes public key)
 * chal: the challenge to the vote (Assumed to have LAMBDA_LENGTH)
 * yesVotePosition: position of the yes vote
 * numberOfCandidates: numberOfCandidates running in the election
OUTPUT
 * verificationCodes: filled with the final verification codes
 * encryptionFactors: filled with the validity factors
 */
 void createReceiptMP2(VerificationCodes* verificationCodes, EncryptionFactors* encryptionFactors,
	 MarkPledgeParameters* param, unsigned char* chal, unsigned char yesVotePosition,
	 unsigned char numberOfCandidates)
 {
	 
	unsigned char testExponent[Q_LENGTH];
	unsigned char aux1[Q_LENGTH + 1];
	unsigned char aux2[Q_LENGTH + 1];
	unsigned char* tx;
	unsigned char* ty;
	int i;
	
	memcpy(&testExponent[Q_LENGTH - LAMBDA_LENGTH], chal, LAMBDA_LENGTH);
	ModularMultiplication(Q_LENGTH, testExponent, param->mp2Param.lambdaTestMultiplier, param->kpub.q);
	
	matrixModPowBySquaring(&(param->mp2Param.so2qGenerator), &mR, testExponent, param->kpub.q);
	tx = mR.a;
	ty = mR.b;

	/*
	compute verification factor, i.e. the vector dot product between the test vector and the 
	random encryption factors of the vote encryption.
	*/
	for(i=0; i < numberOfCandidates; i++)
	{
		aux1[0] = 0;
		memcpy(&aux1[1], encryptionFactors->mp2EncryptionFactors[i].vectorComponentX, Q_LENGTH);
		ModularMultiplication(Q_LENGTH, &aux1[1], tx, param->kpub.q);

		aux2[0] = 0;
		memcpy(&aux2[1], encryptionFactors->mp2EncryptionFactors[i].vectorComponentY, Q_LENGTH);
		ModularMultiplication(Q_LENGTH, &aux2[1], ty, param->kpub.q);

		ADDN(Q_LENGTH+1, aux1, aux1, aux2);
		ModularReduction(Q_LENGTH+1, Q_LENGTH, aux1, param->kpub.q);
		
		memcpy(encryptionFactors->mp2EncryptionFactors[i].validityFactor, &aux1[1], Q_LENGTH);
		
		//update verification code for the non selected candidates
		if(i != yesVotePosition)
		{
			//printf("%d ZERO index: ", i);
			//printArray(verificationCodes->verificationCode[i],3);
			
			subModLambda(verificationCodes->verificationCode[i], chal, 
				verificationCodes->verificationCode[i], param->mp2Param.lambda);
			
			//printf("ONE index: ");
			//printArray(verificationCodes->verificationCode[i],3);
		}				
	}
 }

 /**
  * Create the MP2 canonical vote from the subtraction vector obtained after 
  * computing the vote receipt.
  *
  * voteEncryption: the vote encryptions, i.e. the vote vector encryptions
  * verificationCodes: the receipt ONE vector indexes
  * encryptionFactors: the voteEncryption encryption factors
  * chal: the vote/receipt challenge
  * numberOfCandidates: the number of candidates running in the election
  * param: the MarkPledge parameters
  * canonicalVote: the structure to hold the canonical vote.
  */

 /* session data */
//#pragma melsession
#pragma melstatic
	unsigned char auxFinalCanonicalStep[Q_LENGTH];
	unsigned char auxInverse[Q_LENGTH];
	MP2Vector oneVector;
		


 void createMP2CanonicalVote(MP2VoteEncryption* voteEncryption, VerificationCodes* verificationCodes,
	 EncryptionFactors* encryptionFactors, unsigned char* chal, MarkPledgeParameters* param, 
	 unsigned char numberOfCandidates, CanonicalVote* canonicalVote, CanonicalFactors* canonicalFactors)
 {
	 
	MP2Vector zeroVector;
	MP2Vector subVector;



	 unsigned char* subtractionValue;
	 unsigned char* subtractionValueInverse = oneVector.x;
	 unsigned char* encryptionFactor;
	 unsigned char aux[P_LENGTH];
	 unsigned char zeroVectorIndex[LAMBDA_LENGTH];
	 unsigned char i;

	 CLEARN(Q_LENGTH, auxFinalCanonicalStep);
	 auxFinalCanonicalStep[Q_LENGTH -1] = 2;
	 //CLEARN(Q_LENGTH, auxInverse);
	 //auxInverse[Q_LENGTH -1] = 2;
	 SUBN(Q_LENGTH, auxInverse, param->kpub.q, auxFinalCanonicalStep);

	 for(i=0; i<numberOfCandidates; i++)
	 {
		 subModLambda(zeroVectorIndex, chal, 
				verificationCodes->verificationCode[i], param->mp2Param.lambda); 

		 transformToExponent(0, aux, zeroVectorIndex, param->mp2Param.lambdaMultiplier, param->kpub.q);
		 
		 matrixModPowBySquaring(&(param->mp2Param.so2qGenerator), &mR, aux, param->kpub.q);
		 memcpy(zeroVector.x, mR.a, Q_LENGTH);
		 memcpy(zeroVector.y, mR.b, Q_LENGTH);

		 transformToExponent(1, aux, verificationCodes->verificationCode[i], 
			 param->mp2Param.lambdaMultiplier, param->kpub.q);
		 
		 matrixModPowBySquaring(&(param->mp2Param.so2qGenerator), &mR, aux, param->kpub.q);
		 memcpy(oneVector.x, mR.a, Q_LENGTH);
		 memcpy(oneVector.y, mR.b, Q_LENGTH);

		 subModQ(subVector.x, oneVector.x, zeroVector.x, param->kpub.q);
		 subModQ(subVector.y, oneVector.y, zeroVector.y, param->kpub.q);

		 //compute encrypted vector subtraction
		 if(isZero(subVector.x, Q_LENGTH)==0) //not zero
		 {// work on x component
			 //subtract encrypted x component
			 /* ModularExponentiation(ExponentLength, ModulusLength, Exponent, Modulus, Base, Result) */
			 ModularExponentiation(Q_LENGTH, P_LENGTH, zeroVector.x, param->kpub.p, param->kpub.mpGInv, aux); 
			 ModularMultiplication(P_LENGTH, aux, voteEncryption->tempCandidateEncryption[i].vectorComponentX.y,
				 param->kpub.p);

			 memcpy(canonicalVote->candidateEncryption[i].x, 
				 voteEncryption->tempCandidateEncryption[i].vectorComponentX.x, P_LENGTH);
			 
			 memcpy(canonicalVote->candidateEncryption[i].y, aux, P_LENGTH);

			 subtractionValue = subVector.x;
			 encryptionFactor = encryptionFactors->mp2EncryptionFactors[i].vectorComponentX;

		 }
		 else
		 {// work on y component
			subModQ(subVector.y, oneVector.y, zeroVector.y, param->kpub.q);
			ModularExponentiation(Q_LENGTH, P_LENGTH, zeroVector.y, param->kpub.p, param->kpub.mpGInv, aux); 
			ModularMultiplication(P_LENGTH, aux, voteEncryption->tempCandidateEncryption[i].vectorComponentY.y,
				param->kpub.p);
			memcpy(canonicalVote->candidateEncryption[i].x, 
				voteEncryption->tempCandidateEncryption[i].vectorComponentY.x, P_LENGTH);
			
			memcpy(canonicalVote->candidateEncryption[i].y, aux, P_LENGTH);

			subtractionValue = subVector.y;
			encryptionFactor = encryptionFactors->mp2EncryptionFactors[i].vectorComponentY;
		 }
		 
				

		 //finalize canonical vote computation
		 ModularExponentiation(Q_LENGTH, Q_LENGTH, auxInverse, param->kpub.q, subtractionValue, 
			 subtractionValueInverse);
		 		
		 
		 ModularExponentiation(Q_LENGTH, P_LENGTH, subtractionValueInverse, param->kpub.p,
			 canonicalVote->candidateEncryption[i].x, canonicalVote->candidateEncryption[i].x); 
		 ModularExponentiation(Q_LENGTH, P_LENGTH, auxFinalCanonicalStep, param->kpub.p,
			 canonicalVote->candidateEncryption[i].x, canonicalVote->candidateEncryption[i].x); 
		 

		
		 ModularExponentiation(Q_LENGTH, P_LENGTH, subtractionValueInverse, param->kpub.p,
			 canonicalVote->candidateEncryption[i].y, canonicalVote->candidateEncryption[i].y);
		 ModularExponentiation(Q_LENGTH, P_LENGTH, auxFinalCanonicalStep, param->kpub.p,
			 canonicalVote->candidateEncryption[i].y, canonicalVote->candidateEncryption[i].y);
		
		ModularMultiplication(P_LENGTH, canonicalVote->candidateEncryption[i].y,
			 param->kpub.mpGInv, param->kpub.p);
			

		//store final encryption factor
		memcpy(canonicalFactors->canonicalFactor[i], subtractionValueInverse, Q_LENGTH);
		ModularMultiplication(Q_LENGTH, canonicalFactors->canonicalFactor[i], encryptionFactor, param->kpub.q);
		ModularMultiplication(Q_LENGTH, canonicalFactors->canonicalFactor[i], auxFinalCanonicalStep, param->kpub.q);


	 }
 }


 


 /**
 * Transforms a vector index into the corresponding exponent.
 * Only works for ONE (YESvote) or ZERO (NOvote) vectors.
 * Assumes SO2q order = q-1
 *
 * yesVote: flag that specifies the type of vector: 1 for an ONE vector and 0 for a ZERO vector)
 * vectorIndex: the vector index in the vector class in [0, lambda[ Assumed to by LAMBDA_LENGTH.
 * multiplier: the mp2 lambda multiplier. Assumed to be of length Q_LENGTH.
 * q: the key parameter q
 * exponent: the place to store the exponent. (exponent = vectorIndex * multiplier +- 1)
 */

void transformToExponent(int yesVote, unsigned char* exponent, unsigned char* vectorIndex, unsigned char* multiplier, unsigned char* q)
{

    unsigned char isZero = 1;
    unsigned char aux[Q_LENGTH];
    unsigned char e[Q_LENGTH];
    unsigned char vi[Q_LENGTH];

    int i;
    for(i=0; i<LAMBDA_LENGTH; i++)
        if(vectorIndex[i]!=0)
        {
            isZero = 0;
            break;
        }
    
    memcpy(&vi[Q_LENGTH - LAMBDA_LENGTH], vectorIndex, LAMBDA_LENGTH);

	/*printf("Index: ");
	printArray(vi,20);
	printf("Multiplier: ");
	printArray(multiplier,20);*/

    if(isZero == 1 && yesVote == 1) //the case of a "negative" exponent result
    {
        aux[Q_LENGTH-1] = 2; // assumes SO2q order = q-1
        SUBN(Q_LENGTH, e, q, aux);
        memcpy(exponent, e, Q_LENGTH);
        return;
    }

    /* ModularMultiplication(ModulusLength, Result, A, Modulus) -- outputs result = result * A mod Modulus*/
    
	ModularMultiplication(Q_LENGTH, vi, multiplier, q);
    aux[Q_LENGTH-1] = 1;
    if (yesVote) // -1
    {
        SUBN(Q_LENGTH, e, vi, aux);
    }
    else // +1
    {
        ADDN(Q_LENGTH, e, vi, aux);
    }
    memcpy(exponent, e, Q_LENGTH);

	/*printf("Exponent: ");
	printArray(exponent,20);*/

}





  /** ##################################################################
  *						MP3 
  *  ##################################################################*/
 
/** Prepare the ballot encryptionon, i.e. initial verification codes and encryption factors
INPUT
 * verificationCodes: initially it contains the values encrypted in ccode
 * encryptionFactors: vote encryption factors
 * param: MarkPledge parameters (includes public key)
 * numberOfcandidates: the number of candidates running in the election
OUTPUT
 * verificationCodes: initialized with the values encrypted in the candidate encryption
 * encryptionFactors: vote encryption factors
 */
void prepareBallotMP3(VerificationCodes* verificationCodes, EncryptionFactors* encryptionFactors, 
	MarkPledgeParameters* param, unsigned char numberOfCandidates)
{
	int i;
	for(i=0; i<numberOfCandidates; i++)
	{
		fillRandomLessThanQ(param->kpub.q, encryptionFactors->mp3EncryptionFactors[i].be);
		fillRandomLessThanQ(param->kpub.q, encryptionFactors->mp3EncryptionFactors[i].ccode);
		fillRandomLessThanQ(param->kpub.q, verificationCodes->verificationCodeMP3[i]);
		
	}
}


/** Create the vote encryption
INPUT
 * verificationCodes: initially it contains the values encrypted in ccode
 * encryptionFactors: vote encryption factors
 * param: MarkPledge parameters (includes public key)
 * isYesVote: 1 if the candidate encryption is for a yes vote and 0 otherwise
 * candidateIndex: the candidate encryption index
OUTPUT
 * voteEncryption: the vote encryption storage structure
 */
void createCandidateEncryptionMP3(VerificationCodes* verificationCodes, 
	EncryptionFactors* encryptionFactors, VoteEncryption* voteEncryption, 
	MarkPledgeParameters* param, unsigned char isYesVote, unsigned char candidateIndex)
{
	 /* create be encryption */
	if(isYesVote == 1)
	{
		exponentialElGamalEncryptionMPG(&param->kpub,
		encryptionFactors->mp3EncryptionFactors[candidateIndex].be,
		&voteEncryption->voteEncryption.mp3.candidateEncryption.be);
	}
	else
	{
		exponentialElGamalEncryptionMPGInv(&param->kpub,
		encryptionFactors->mp3EncryptionFactors[candidateIndex].be,
		&voteEncryption->voteEncryption.mp3.candidateEncryption.be);
	}

	/* create ccode encryption */
	exponentialElGamalEncryption(&param->kpub,
		verificationCodes->verificationCodeMP3[candidateIndex],
		encryptionFactors->mp3EncryptionFactors[candidateIndex].ccode,
		&voteEncryption->voteEncryption.mp3.candidateEncryption.ccode);

}



 /** Create the vote receipt, i.e. vcode and vcodeFactor values
INPUT
 * verificationCodes: initially it contains the values encrypted in ccode
 * encryptionFactors: vote encryption factors
 * kpub: public key
 * chal: the challenge to the vote
 * yesVotePosition: position of the yes vote
 * numberOfCandidates: numberOfCandidates running in the election
OUTPUT
 * verificationCodes: filled with the final verification codes
 * encryptionFactors->validityFactor: the verification code validity factor
 */

//necessary for Q of 512 bits
//#pragma melstatic
 
 
 void createReceiptMP3(VerificationCodes* verificationCodes,
	 EncryptionFactors* encryptionFactors,
	 MarkPledgeParameters *param,
	 unsigned char* chal,
	 unsigned char yesVotePosition,
	 unsigned char numberOfCandidates)
 {
/* ModularMultiplication(ModulusLength, Result, A, Modulus) -- outputs result = result * A mod Modulus
/* ModularReduction(OperandLength, ModulusLength, Operand, Modulus) */

    /* auxiliary variables to perform some required modular functions */
   unsigned char auxChal[Q_LENGTH + 1];
	unsigned char aux2Chal[Q_LENGTH + 1];
	 unsigned char vcodeAux[Q_LENGTH + 1];


    unsigned char aux1[Q_LENGTH + 1];
    unsigned char aux2[Q_LENGTH + 1];
    unsigned char aux3[Q_LENGTH + 1];

    int i;

	MP3CandidateEncryptionFactors* encFactors = encryptionFactors->mp3EncryptionFactors;
	ExponentialElGamalPublicKey* kpub = &param->kpub; 

    auxChal[0] = 0;
    memcpy(&auxChal[1], chal, Q_LENGTH); /* auxChal = chal */
    ADDN(Q_LENGTH+1, aux2Chal, auxChal, auxChal); /* aux2Chal = 2.chal */
    ModularReduction(Q_LENGTH + 1, Q_LENGTH, aux2Chal, kpub->q); /* aux2Chal = 2.chal-ccode mod q */


    for(i=0; i<numberOfCandidates; i++)
    {
        /* yes votes */
        /*vcode = ccode */
        
		 /* no votes */
		/*vcode = 2.chal - ccode*/
        if (i != yesVotePosition)
        {   
            aux1[0] = 0;
			// ccode is stored in the verification code structure
			memcpy(&aux1[1], verificationCodes->verificationCodeMP3[i], Q_LENGTH); /* aux1 = ccode */
            /**
            SUBN(Q_LENGTH+1, aux2, aux2Chal, aux1); /* aux2 = 2.chal-ccode mod q*/
            subModQ(&aux2[1], &aux2Chal[1], &aux1[1], kpub->q);

            memcpy(verificationCodes->verificationCodeMP3[i], &aux2[1], Q_LENGTH);
        }

        vcodeAux[0] = 0;
        memcpy(&vcodeAux[1], verificationCodes->verificationCodeMP3[i], Q_LENGTH);


        /* create and store the vcodeFactor */
        /* step 1 : res = chal - vcode mod q*/
        /**
        SUBN(Q_LENGTH+1, aux1, auxChal, vcodeAux); /* aux1 = chal-vcode
        ModularReduction(Q_LENGTH + 1, Q_LENGTH, aux1, kpub->q); /* aux1 = chal-vcode mod q */
        subModQ(&aux1[1], &auxChal[1], &vcodeAux[1], kpub->q);

		ModularMultiplication(Q_LENGTH, &aux1[1], encFactors[i].be, kpub->q); /* aux1 = (chal-vcode).beFactor mod q */
        aux1[0] = 0;
        aux2[0] = 0;
		memcpy(&aux2[1], encFactors[i].ccode, Q_LENGTH); /* aux2 = ccodeFactor */
        ADDN(Q_LENGTH+1, aux3, aux1, aux2); /* aux3 = ((chal-vcode).beFactor mod q) + ccodeFactor*/
        ModularReduction(Q_LENGTH + 1, Q_LENGTH, aux3, kpub->q); /* aux3 = (chal-vcode).beFactor + ccodeFactor mod q */
		memcpy(encFactors[i].validityFactor, &aux3[1], Q_LENGTH); /* store vcodeFactor */
    
		
	}
 }



