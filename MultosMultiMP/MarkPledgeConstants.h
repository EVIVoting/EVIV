/*
 * MarkPledgeConstants.h
 *
 *  Created on: 23 de Mai de 2011
 *      Author: Rui
 */

#ifndef MARKPLEDGE_CONSTANTS_H_INCLUDE
#define MARKPLEDGE_CONSTANTS_H_INCLUDE

#define BALLOT_TYPE_MP1 			0
#define BALLOT_TYPE_MP1A 			1
#define	BALLOT_TYPE_MP2 			2
#define	BALLOT_TYPE_MP3				3


#define P_LENGTH 			128	// modulus p length in bytes
#define Q_LENGTH 			20	// modulus q length in bytes
#define MAX_CANDIDATES 		4 	// maximum number of candidates supported (this limit is low because of the length of the MP1 candidate encryption)
#define MAX_CANDIDATES_FLAG	0x0F

#define MAX_ALPHA			24  // max alpha in bits (specific to MP1)
#define ALPHA_BITS_BYTE_LENGTH	3  	// alpha is always represented in 3 bytes
#define LAMBDA_LENGTH			ALPHA_BITS_BYTE_LENGTH

#define VOTE_CODE_LENGTH	8 	// vote code length in bytes
#define HASH_LENGTH			20	// SHA-1 hash length in bytes




#endif /* MARKPLEDGECONSTANTS_H_INCLUDE */
