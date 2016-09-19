/*
 * main.c
 *
 *  Created on: 23 de Mai de 2011
 *      Author: Rui
 *
 *
 * IMPORTANT NOTE:	The code below is only a demostration. It assumes a honest vote client application.
 *					Therefore it DOES NOT implement a state machine to prevent malicious command sequences.
 */

/* TODO: update info */
#pragma attribute("aid", "f0 00 00 00 02 04")
#pragma attribute("dir", "61 10 4f 6 f0 00 00 00 02 04 50 4 6d 61 74 68")

#include <stdio.h>
#include <string.h>
#include <multoscomms.h>
#include <multoscrypto.h>
#include <multosarith.h>

#include "MarkPledgeConstants.h"
#include "MarkPledgeAPDUs.h"
#include "DataStructures.h"
#include "MarkPledgeCrypto.h"
#include "Util.h"



/* ISO APDU type case definitions */
#define NODATAIN_NODATAOUT  1
#define NODATAIN_DATAOUT    2
#define DATAIN_NODATAOUT    3
#define DATAIN_DATAOUT      4


#define ERR_COMMAND_NOT_ALLOWED         0x6900 /* used if an error occurs when checking the  APDU case */
#define ERR_INVALID_CANDIDATE_SELECTION 0x6901
#define ERR_ILLEGAL_STATE				0x6902	/* used when a command is out of the control sequence */
#define ERR_WRONG_P1P2                  0x6B00
#define ERR_INS_NOT_SUPPORTED           0x6D00
#define ERR_CLA_NOT_SUPPORTED           0x6E00
#define ERR_NO_PRECISE_DIAGNOSTIC       0x6F00
#define ERR_WRONG_INPUT_LENGTH          0x6700
#define ERR_EXPECTED_P_LENGTH_OUTPUT    (0x6C00 + P_LENGTH)
#define ERR_EXPECTED_Q_LENGTH_OUTPUT    (0x6C00 + Q_LENGTH)
#define ERR_EXPECTED_ONE_BYTE_OUTPUT    0x6C01
#define ERR_EXPECTED_ALPHA_BYTE_LENGTH	(0x6C00 + ALPHA_BITS_BYTE_LENGTH)
#define ERR_EXPECTED_HASH_LENGTH_OUTPUT (0x6C00 + HASH_LENGTH)



/* public data */
#pragma melpublic
/* Data from APDU; this is placed at PB[0] */
union
{
  unsigned char inputP[P_LENGTH];
  unsigned char inputQ[Q_LENGTH];
  unsigned char inputALPHA[ALPHA_BITS_BYTE_LENGTH];
  unsigned char inputCandidateSelection[VOTE_CODE_LENGTH];
  unsigned char outputP[P_LENGTH];
  unsigned char outputQ[Q_LENGTH];
  unsigned char outputALPHA[ALPHA_BITS_BYTE_LENGTH];
  unsigned char outputHash[HASH_LENGTH];
  unsigned char outputOneByte;
} APDUdata;


/* session data */
//#pragma melsession
#pragma melstatic
Matrix mA,mAux,mR;


/* static data */
#pragma melstatic
MarkPledgeParameters param;
SharedVoteEncryptionAndProofStructure voteData;

/* Initially hold the "encrypted values" in the candidate encryptions.
   When the challenge is set and the receipt computed, then it contains the verification codes */
VerificationCodes verificationCodes;
EncryptionFactors encryptionFactors;
CanonicalVote canonicalVote;
CanonicalFactors canonicalFactors;
unsigned char yesVotePosition;
unsigned char numberOfCandidates;
unsigned char ballotType = BALLOT_TYPE_MP3;







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
void (*prepareBallot[4])(VerificationCodes*, EncryptionFactors*, MarkPledgeParameters*,
					  unsigned char) =
	{
		&prepareBallotMP1,
		&prepareBallotMP1A,
		&prepareBallotMP2,
		&prepareBallotMP3
	};


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
void (*createCandidateEncryption[4])(VerificationCodes*, EncryptionFactors*, VoteEncryption*,
	MarkPledgeParameters*, unsigned char, unsigned char) =
	{
		&createCandidateEncryptionMP1,
		&createCandidateEncryptionMP1A,
		&createCandidateEncryptionMP2,
		&createCandidateEncryptionMP3
	};


 /** Create the vote receipt, i.e. vcode and vcodeFactor values
INPUT
 * verificationCodes: initially it contains the values encrypted in ccode
 * encryptionFactors: vote encryption factors
 * param: MarkPledge parameters (includes public key)
 * chal: the challenge to the vote
 * yesVotePosition: position of the yes vote
 * numberOfCandidates: numberOfCandidates running in the election
OUTPUT
 * verificationCodes: filled with the final verification codes
 * encryptionFactors: filled with the validity factors
 */
void (*createReceipt[4])(VerificationCodes*, EncryptionFactors*, MarkPledgeParameters* ,
	 unsigned char*, unsigned char,	unsigned char) =
	{
		&createReceiptMP1,
		&createReceiptMP1A,
		&createReceiptMP2,
		&createReceiptMP3
	};


/* 
 * Method to copy the canonical vote in MP3 and MP1A vote encryptions
 */
void copyCanonicalVote(unsigned char position)
{
	unsigned char* pointerX;
	unsigned char* pointerY;
	unsigned char* canonicalFactor;

	switch(ballotType)
	{
		case BALLOT_TYPE_MP1A:
			pointerX = voteData.voteEncryption.voteEncryption.mp1A.canonicalVote.x;
			pointerY = voteData.voteEncryption.voteEncryption.mp1A.canonicalVote.y;
			canonicalFactor = encryptionFactors.mp1AEncryptionFactors[position].canonicalVoteFactor;
			break;
		case BALLOT_TYPE_MP3:
			pointerX = voteData.voteEncryption.voteEncryption.mp3.candidateEncryption.be.x;
			pointerY = voteData.voteEncryption.voteEncryption.mp3.candidateEncryption.be.y;
			canonicalFactor = encryptionFactors.mp3EncryptionFactors[position].be;
			break;
		default: 
			return;
	}

	memcpy(canonicalVote.candidateEncryption[position].x, pointerX, P_LENGTH);
	memcpy(canonicalVote.candidateEncryption[position].y, pointerY, P_LENGTH);
	memcpy(canonicalFactors.canonicalFactor[position], canonicalFactor, Q_LENGTH);
}

/*
 * Method to sum the canonical factors
 */
void sumCanonicalFactors(void)
{
/* ModularReduction(OperandLength, ModulusLength, Operand, Modulus) */

    unsigned char aux[Q_LENGTH + 1];
    unsigned char res[Q_LENGTH + 1];
    int i;

    aux[0] = 0;
    res[0] = 0;
	memcpy(&res[1], canonicalFactors.canonicalFactor[0], Q_LENGTH);

    for(i=1; i<numberOfCandidates; i++)
    {
        memcpy(&aux[1], canonicalFactors.canonicalFactor[i], Q_LENGTH);
        ADDN(Q_LENGTH+1, res, res, aux); /* res += aux */
    }
    ModularReduction(Q_LENGTH + 1, Q_LENGTH, res, param.kpub.q); /* res = 2.chal-ccode mod q */
	memcpy(canonicalVote.voteSumFactor, &res[1], Q_LENGTH);
}

void adjustAlphaOutput(void)
{
	unsigned aux;
	if(ballotType == BALLOT_TYPE_MP1 || ballotType == BALLOT_TYPE_MP1A)
	{
		//adjust the output to the alpha size
		aux = MAX_ALPHA - param.alpha;
		while(aux > 0)
		{
			ASSIGN_SHRN(ALPHA_BITS_BYTE_LENGTH, APDUdata.outputQ, 1);
			aux--;
		}
	}
}

void adjustAlphaInput(void)
{
	unsigned aux;
	if(ballotType == BALLOT_TYPE_MP1 || ballotType == BALLOT_TYPE_MP1A)
	{
		//adjust the input to the alpha size
		aux = MAX_ALPHA - param.alpha;
		while(aux > 0)
		{
			ASSIGN_SHLN(ALPHA_BITS_BYTE_LENGTH, APDUdata.inputQ, 1);
			aux--;
		}
	}
}

void main(void)
{
	unsigned char randomData[8];
	int i, aux;

	switch(CLA)
	{
	/*###########################################################*
	 * 						SET APDUS							 *
	 *###########################################################*/
		case CLA_SET_P_LENGTH:
			// verify APDU type
			if(!CheckCase(DATAIN_NODATAOUT))
				ExitSW(ERR_COMMAND_NOT_ALLOWED | CLA_SET_P_LENGTH);
			// verify input length
            if(Lc != P_LENGTH)
                ExitSW(ERR_WRONG_INPUT_LENGTH);

			switch(INS)
			{
				case INS_SET_P:
					memcpy(param.kpub.p, APDUdata.inputP, P_LENGTH);
					break;
				case INS_SET_G:
					memcpy(param.kpub.g, APDUdata.inputP, P_LENGTH);
					break;
				case INS_SET_H:
					memcpy(param.kpub.h, APDUdata.inputP, P_LENGTH);
					break;
				case INS_SET_MP_G:
					memcpy(param.kpub.mpG, APDUdata.inputP, P_LENGTH);
					break;
				case INS_SET_MP_GINV:
					memcpy(param.kpub.mpGInv, APDUdata.inputP, P_LENGTH);
					break;
				default:
					ExitSW(ERR_INS_NOT_SUPPORTED);
			}
			Exit();

		case CLA_SET_Q_LENGTH:
			// verify APDU type
			if(!CheckCase(DATAIN_NODATAOUT))
				ExitSW(ERR_COMMAND_NOT_ALLOWED | CLA_SET_Q_LENGTH);
			// verify input length
            if(Lc != Q_LENGTH)
                ExitSW(ERR_WRONG_INPUT_LENGTH);

			switch(INS)
			{
				case INS_SET_Q:
					memcpy(param.kpub.q, APDUdata.inputQ, Q_LENGTH);
					break;
				case INS_SET_MP2_GV_X:
					memcpy(param.mp2Param.so2qGenerator.a, APDUdata.inputQ, Q_LENGTH);
					memcpy(param.mp2Param.so2qGenerator.d, APDUdata.inputQ, Q_LENGTH);
					break;
				case INS_SET_MP2_GV_Y:
					memcpy(param.mp2Param.so2qGenerator.b, APDUdata.inputQ, Q_LENGTH);
					SUBN(Q_LENGTH, param.mp2Param.so2qGenerator.c, param.kpub.q, param.mp2Param.so2qGenerator.b);
					break;
				case INS_SET_LAMBDA_MULTIPLIER:
					memcpy(param.mp2Param.lambdaMultiplier, APDUdata.inputQ, Q_LENGTH);
					//lambdaTestMultiplier = lambdaMultiplier / 2
					memcpy(param.mp2Param.lambdaTestMultiplier, APDUdata.inputQ, Q_LENGTH);
					ASSIGN_SHRN(Q_LENGTH, param.mp2Param.lambdaTestMultiplier, 1);
					break;
				default:
					ExitSW(ERR_INS_NOT_SUPPORTED);
			}
			Exit();

		case CLA_SET_ALPHA_BITS_BYTE_LENGTH:
			// verify APDU type
			if(!CheckCase(DATAIN_NODATAOUT))
				ExitSW(ERR_COMMAND_NOT_ALLOWED | CLA_SET_ALPHA_BITS_BYTE_LENGTH);
			// verify input length
            if(Lc != ALPHA_BITS_BYTE_LENGTH)
                ExitSW(ERR_WRONG_INPUT_LENGTH);

			switch(INS)
			{
				case INS_SET_LAMBDA:
					memcpy(param.mp2Param.lambda, APDUdata.inputALPHA, LAMBDA_LENGTH);
					break;
				default:
					ExitSW(ERR_INS_NOT_SUPPORTED);
			}
			Exit();

		case CLA_SET_VALUE_IN_P1P2:
			// verify APDU type
			if(!CheckCase(NODATAIN_NODATAOUT))
				ExitSW(ERR_COMMAND_NOT_ALLOWED | CLA_SET_VALUE_IN_P1P2);

			switch(INS)
			{
				case INS_SET_ALPHA:
					if (P1 > MAX_ALPHA)
						ExitSW(ERR_WRONG_P1P2);
					param.alpha = P1;
					break;
				default:
					ExitSW(ERR_INS_NOT_SUPPORTED);
			}
			Exit();

	/*###########################################################*
	 * 						ACTION APDUS						 *
	 *###########################################################*/

		case CLA_ACTION_WHITHOUT_DATA_INPUT:
			// verify APDU type
			if(!CheckCase(NODATAIN_NODATAOUT))
				ExitSW(ERR_COMMAND_NOT_ALLOWED | CLA_ACTION_WHITHOUT_DATA_INPUT);

			switch(INS)
			{
				case INS_PREPARE_BALLOT:
					// verify parameter P1
					if(P1 > MAX_CANDIDATES)
				        ExitSW(ERR_WRONG_P1P2);
					// verify parameter P2
					if(P2 > BALLOT_TYPE_MP3)
				        ExitSW(ERR_WRONG_P1P2);

					numberOfCandidates = P1;
					ballotType = P2;

					prepareBallot[ballotType](&verificationCodes, &encryptionFactors, &param, numberOfCandidates);

					/* select yes vote position */
					while(1){
						GetRandomNumber(randomData);
						i = 0;
						do{
							aux = randomData[i] & MAX_CANDIDATES_FLAG;
							i++;
							if (aux < numberOfCandidates)
							{
								yesVotePosition = aux;
								Exit();
							}
						} while(i<8);
					}


				case INS_CREATE_CANDIDATE_ENCRYPTION:
					// verify parameter P1
					if(P1 > MAX_CANDIDATES)
				        ExitSW(ERR_WRONG_P1P2);

					if(P1 == yesVotePosition)
						i=1;
					else
						i=0;

					createCandidateEncryption[ballotType](&verificationCodes, &encryptionFactors,
						&voteData.voteEncryption,
						&param, i, P1);

					copyCanonicalVote(P1);

					break;

				case INS_CREATE_CGS97_CANDIDATE_PROOF:
					// verify parameter P1
					if(P1 > MAX_CANDIDATES)
				        ExitSW(ERR_WRONG_P1P2);

					if(P1 == yesVotePosition)
						i=1;
					else
						i=0;

					memcpy(voteData.cgs97Proof.canonicalVote.x, canonicalVote.candidateEncryption[P1].x, P_LENGTH);
					memcpy(voteData.cgs97Proof.canonicalVote.y, canonicalVote.candidateEncryption[P1].y, P_LENGTH);

					createCGS97Proof(&param.kpub, canonicalFactors.canonicalFactor[P1],	&voteData.cgs97Proof, i);

					
					break;

				case INS_CREATE_MP2_CANONICAL_VOTE:
					createMP2CanonicalVote(&voteData.voteEncryption.voteEncryption.mp2, 
						&verificationCodes,	&encryptionFactors, 
						voteData.voteEncryption.hashStructure.challenge, &param,
						numberOfCandidates, &canonicalVote, &canonicalFactors);
					break;
				default:
					ExitSW(ERR_INS_NOT_SUPPORTED);
			}
			Exit();

		case CLA_ACTION_WHITH_DATA_INPUT:
			// verify APDU type
			if(!CheckCase(DATAIN_NODATAOUT))
				ExitSW(ERR_COMMAND_NOT_ALLOWED | CLA_ACTION_WHITH_DATA_INPUT);

			switch(INS)
			{
				case INS_PREPARE_RECEIPT:
					if(ballotType == BALLOT_TYPE_MP3)
						aux = Q_LENGTH;
					else {
						aux = ALPHA_BITS_BYTE_LENGTH;
						adjustAlphaInput();
					}
						
					//verify input length
					if (Lc != aux)
						ExitSW(ERR_WRONG_INPUT_LENGTH);
										
					memcpy(voteData.voteEncryption.hashStructure.challenge, APDUdata.inputQ, aux);
					
					createReceipt[ballotType](&verificationCodes, &encryptionFactors, &param,
						voteData.voteEncryption.hashStructure.challenge, yesVotePosition, numberOfCandidates);
					break;

				case INS_CREATE_MP2_CANONICAL_VOTE_WITH_HELP:
					//TODO
				default:
					ExitSW(ERR_INS_NOT_SUPPORTED);
			}
			Exit();

		case CLA_ACTION_WHITH_DATA_INPUT_AND_OUTPUT:
			// verify APDU type
			if(!CheckCase(DATAIN_DATAOUT))
				ExitSW(ERR_COMMAND_NOT_ALLOWED | CLA_ACTION_WHITH_DATA_INPUT_AND_OUTPUT);
			switch(INS)
			{
				case INS_SELECT_CANDIDATE:
					// TODO decode candidate code
					/* verify input length */

					if(Lc != VOTE_CODE_LENGTH)
						ExitSW(ERR_WRONG_INPUT_LENGTH);

					/* get selected candidate */
					/** TODO: Translate vote code *
					for now the first byte representd the index of the selected candidate*/

					aux = APDUdata.inputCandidateSelection[VOTE_CODE_LENGTH-1];
					if (aux >= numberOfCandidates)
						ExitSW(ERR_INVALID_CANDIDATE_SELECTION);

					/* set rotation */
					i = aux - yesVotePosition;
					if (i < 0)
						i += numberOfCandidates;

					APDUdata.outputOneByte = i;
					ExitLa(1);


				default:
					ExitSW(ERR_INS_NOT_SUPPORTED);
			}
			break;

	/*###########################################################*
	 * 						GET APDUS							 *
	 *###########################################################*/

		case CLA_GET_RECEIPT_DATA:
			// verify APDU type
			if(!CheckCase(NODATAIN_DATAOUT))
				ExitSW(ERR_COMMAND_NOT_ALLOWED | CLA_GET_RECEIPT_DATA);

			//verify output expected length
			if((ballotType == BALLOT_TYPE_MP3 || INS == INS_GET_VCODE_VALIDITY_FACTOR))
			{
			    if (Le != Q_LENGTH)
                    ExitSW(ERR_EXPECTED_Q_LENGTH_OUTPUT);
			}
			else if (Le != ALPHA_BITS_BYTE_LENGTH)
			{
				ExitSW(ERR_EXPECTED_ALPHA_BYTE_LENGTH);
			}

			if(ballotType == BALLOT_TYPE_MP3)
				aux = Q_LENGTH;
			else
				aux = ALPHA_BITS_BYTE_LENGTH;

			switch(INS)
			{
				case INS_GET_PLEDGE:
					if(ballotType == BALLOT_TYPE_MP3)
						memcpy(APDUdata.outputQ, verificationCodes.verificationCodeMP3[yesVotePosition], aux);
					else{
						memcpy(APDUdata.outputQ, verificationCodes.verificationCode[yesVotePosition], aux);
						adjustAlphaOutput();
					}
					ExitLa(aux);

				case INS_GET_VCODE:
					
					if(P1 >= numberOfCandidates)
						ExitSW(ERR_WRONG_P1P2);

					if(ballotType == BALLOT_TYPE_MP3)
						memcpy(APDUdata.outputQ, verificationCodes.verificationCodeMP3[P1], aux);
					else{
						memcpy(APDUdata.outputQ, verificationCodes.verificationCode[P1], aux);
						adjustAlphaOutput();
					}

					//printf("Get VC %d: ", P1);
					//printArray(APDUdata.outputQ, 20);
					
					ExitLa(aux);

				case INS_GET_VCODE_VALIDITY_FACTOR:
					// verify P1 parameter
					if (P1 > numberOfCandidates)
						ExitSW(ERR_WRONG_P1P2);

					// verify P2 parameter
						if (P2 > param.alpha)
							ExitSW(ERR_WRONG_P1P2);

					//verify the ballot type
					switch(ballotType)
					{
						case BALLOT_TYPE_MP1:
							// the bmp open element verification factor is stored in the lefth position
							// this position is shared due to memory restrictions
							memcpy(APDUdata.outputQ, encryptionFactors.mp1EncryptionFactors[P1].bmpFactor[P2].left, Q_LENGTH);
							break;

						case BALLOT_TYPE_MP1A:
							// the bmp open element verification factor is stored in the lefth position
							// this position is shared due to memory restrictions
							memcpy(APDUdata.outputQ, encryptionFactors.mp1AEncryptionFactors[P1].bmpFactor[P2].left, Q_LENGTH);
							break;

						case BALLOT_TYPE_MP2:
							memcpy(APDUdata.outputQ, encryptionFactors.mp2EncryptionFactors[P1].validityFactor, Q_LENGTH);
							break;

						case BALLOT_TYPE_MP3:
							memcpy(APDUdata.outputQ, encryptionFactors.mp3EncryptionFactors[P1].validityFactor, Q_LENGTH);
							break;
					}
					ExitLa(Q_LENGTH);

				default:
					ExitSW(ERR_INS_NOT_SUPPORTED);
			}
			Exit();

		case CLA_GET_CANDIDATE_ENCRYPTION:
			// verify APDU type
			if(!CheckCase(NODATAIN_DATAOUT))
				ExitSW(ERR_COMMAND_NOT_ALLOWED | CLA_GET_CANDIDATE_ENCRYPTION);

			//verify output expected length
			if(Le != P_LENGTH)
				ExitSW(ERR_EXPECTED_P_LENGTH_OUTPUT);

			//verify valid P1
			if((P1 > 1 && ((ballotType == BALLOT_TYPE_MP2) || (ballotType == BALLOT_TYPE_MP2)))
					|| (P1 >= (2 * param.alpha) && ballotType == BALLOT_TYPE_MP1)
					|| (P1 > (2 * param.alpha) && ballotType == BALLOT_TYPE_MP1A))
				ExitSW(ERR_WRONG_P1P2);

			switch(INS)
			{
				case INS_GET_CANDIDATE_ENCRYPTION_X:
					memcpy(APDUdata.outputP, voteData.voteEncryption.voteEncryption.encryptions[P1].x, P_LENGTH);
					ExitLa(P_LENGTH);

				case INS_GET_CANDIDATE_ENCRYPTION_Y:
					memcpy(APDUdata.outputP, voteData.voteEncryption.voteEncryption.encryptions[P1].y, P_LENGTH);
					ExitLa(P_LENGTH);

				default:
					ExitSW(ERR_INS_NOT_SUPPORTED);
			}
			Exit();

		case CLA_GET_P_LENGTH_CANONICAL_VOTE_PROOF_DATA:
			// verify APDU type
			if(!CheckCase(NODATAIN_DATAOUT))
				ExitSW(ERR_COMMAND_NOT_ALLOWED | CLA_GET_P_LENGTH_CANONICAL_VOTE_PROOF_DATA);

			//verify output expected length
			if(Le != P_LENGTH)
				ExitSW(ERR_EXPECTED_P_LENGTH_OUTPUT);

			switch(INS)
			{
				case INS_GET_CGS97_A1:
					memcpy(APDUdata.outputP, voteData.cgs97Proof.a1, P_LENGTH);
					ExitLa(P_LENGTH);

				case INS_GET_CGS97_A2:
					memcpy(APDUdata.outputP, voteData.cgs97Proof.a2, P_LENGTH);
					ExitLa(P_LENGTH);

				case INS_GET_CGS97_B1:
					memcpy(APDUdata.outputP, voteData.cgs97Proof.b1, P_LENGTH);
					ExitLa(P_LENGTH);

				case INS_GET_CGS97_B2:
					memcpy(APDUdata.outputP, voteData.cgs97Proof.b2, P_LENGTH);
					ExitLa(P_LENGTH);

				default:
					ExitSW(ERR_INS_NOT_SUPPORTED);
			}
			Exit();

		case CLA_GET_Q_LENGTH_CANONICAL_VOTE_PROOF_DATA:
			// verify APDU type
			if(!CheckCase(NODATAIN_DATAOUT))
				ExitSW(ERR_COMMAND_NOT_ALLOWED | CLA_GET_Q_LENGTH_CANONICAL_VOTE_PROOF_DATA);

			//verify output expected length
			if(Le != Q_LENGTH)
				ExitSW(ERR_EXPECTED_Q_LENGTH_OUTPUT);

			switch(INS)
			{
				case INS_GET_CGS97_D1:
					memcpy(APDUdata.outputQ, voteData.cgs97Proof.d1, Q_LENGTH);
					ExitLa(Q_LENGTH);

				case INS_GET_CGS97_D2:
					memcpy(APDUdata.outputQ, voteData.cgs97Proof.d2, Q_LENGTH);
					ExitLa(Q_LENGTH);

				case INS_GET_CGS97_R1:
					memcpy(APDUdata.outputQ, voteData.cgs97Proof.r1, Q_LENGTH);
					ExitLa(Q_LENGTH);

				case INS_GET_CGS97_R2:
					memcpy(APDUdata.outputQ, voteData.cgs97Proof.r2, Q_LENGTH);
					ExitLa(Q_LENGTH);

				case INS_GET_CGS97_C:
					memcpy(APDUdata.outputQ, voteData.cgs97Proof.c, Q_LENGTH);
					ExitLa(Q_LENGTH);

				case INS_GET_SUM_VALIDITY_FACTOR:
					sumCanonicalFactors();
					memcpy(APDUdata.outputQ, canonicalVote.voteSumFactor, Q_LENGTH);
					ExitLa(Q_LENGTH);

				case INS_GET_MP1A_BMP_CONFORMITY_PROOF:
					// verify the correct ballot type
					if(ballotType != BALLOT_TYPE_MP1A)
						ExitSW(ERR_ILLEGAL_STATE);
					// verify parameters
					if (P1 > numberOfCandidates || P2 >= param.alpha)
						ExitSW(ERR_WRONG_P1P2);

					// the bmp conformity factor is stored in the rigth position
					memcpy(APDUdata.outputQ, encryptionFactors.mp1AEncryptionFactors[P1].bmpFactor[P2].right, Q_LENGTH);
					ExitLa(Q_LENGTH);

				default:
					ExitSW(ERR_INS_NOT_SUPPORTED);
			}
			Exit();

		case CLA_GET_HASH_AND_SIGNATURE:
			// verify APDU type
			if(!CheckCase(NODATAIN_DATAOUT))
				ExitSW(ERR_COMMAND_NOT_ALLOWED | CLA_GET_HASH_AND_SIGNATURE);

			switch(INS)
			{
				case INS_GET_VOTE_ENCRYPTION_SIGNATURE:
					//TODO
				case INS_GET_VOTE_AND_RECEIPT_SIGNATURE:
					//TODO
					ExitLa(P_LENGTH);

				case INS_GET_VOTE_HASH:
					//verify output expected length
					if(Le != HASH_LENGTH)
						ExitSW(ERR_EXPECTED_HASH_LENGTH_OUTPUT);

					memcpy(APDUdata.outputHash, voteData.voteEncryption.hashStructure.voteHash, HASH_LENGTH);
					ExitLa(HASH_LENGTH);

				case INS_GET_VOTE_AND_RECEIPT_HASH:
					//verify output expected length
					if(Le != HASH_LENGTH)
						ExitSW(ERR_EXPECTED_HASH_LENGTH_OUTPUT);

					memcpy(APDUdata.outputHash, voteData.voteEncryption.hashStructure.voteReceiptHash, HASH_LENGTH);
					ExitLa(HASH_LENGTH);

				default:
					ExitSW(ERR_INS_NOT_SUPPORTED);
			}
			Exit();


		default:
			   ExitSW(ERR_CLA_NOT_SUPPORTED);
	 }

	/* This should not happen */
	 ExitSW(ERR_NO_PRECISE_DIAGNOSTIC);
}































