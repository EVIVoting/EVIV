/*
 * MarkPledgeAPDUs.h
 *
 *  Created on: 23 de Mai de 2011
 *      Author: Rui
 */

#ifndef MARKPLEDGE_APDUS_H_INCLUDE
#define MARKPLEDGE_APDUS_H_INCLUDE

#include "MarkPledgeConstants.h"

/*###########################################################*
 * 						SET APDUS							 *
 *###########################################################*/

/*
Instruction		CLA	INS	P1	P2	LC  	   Data
---------------------------------------------------
SET_P	        F0	00	-	-	P_LENGTH	P
SET_G			F0	01	-	-	P_LENGTH	G
SET_H			F0	02	-	-	P_LENGTH	H
SET_MP_G		F0	03	-	-	P_LENGTH	MP_G
SET_MP_GINV		F0	04	-	-	P_LENGTH	MP_GINV
*/
#define CLA_SET_P_LENGTH 	0xF0

#define INS_SET_P			0x00
#define INS_SET_G			0x01
#define INS_SET_H			0x02
#define INS_SET_MP_G		0x03
#define INS_SET_MP_GINV		0x04

/*
Instruction				CLA	INS	P1	P2	LC  	   			Data
---------------------------------------------------------------------------
SET_Q	        		F1	00	-	-	Q_LENGTH	Q
SET_MP2_GV_X			F1	01	-	-	Q_LENGTH	MP2 vector component X
SET_MP2_GV_Y			F1	02	-	-	Q_LENGTH	MP2 vector component Y
SET_LAMBDA_MULTIPLIER	F1	03	-	-	Q_LENGTH	MP2 lambda multiplier
*/
#define CLA_SET_Q_LENGTH 	0xF1

#define INS_SET_Q					0x00
#define INS_SET_MP2_GV_X			0x01
#define INS_SET_MP2_GV_Y			0x02
#define INS_SET_LAMBDA_MULTIPLIER	0x03

/*
Instruction				CLA	INS	P1	P2	LC  	   				Data
---------------------------------------------------------------------------
SET_LAMBDA	       		F2	00	-	-	ALPHA_BITS_BYTE_LENGTH	MP2 lambda
*/
#define CLA_SET_ALPHA_BITS_BYTE_LENGTH 	0xF2
#define INS_SET_LAMBDA					0x00

/*
Instruction				CLA	INS	P1		P2	LC	Data
-----------------------------------------------------
SET_ALPHA	       		F3	00	alpha	-	-	-
*/
#define CLA_SET_VALUE_IN_P1P2 	0xF3
#define INS_SET_ALPHA			0x00



/*###########################################################*
 * 						ACTION APDUS						 *
 *###########################################################*/

/*
Instruction						CLA	INS	P1	P2	LC
---------------------------------------------------
PREPARE_BALLOT	        		F5	00	XX	XX	-		P1 = candidate index, P2 = ballot type
PREPARE_CANDIDATE_ENCRYPTION	F5	01	XX	-	-		P1 = candidate index
CREATE_CGS97_CANDIDATE_PROOF	F5	02	XX	-	-		P1 = candidate index
CREATE_MP2_CANONICAL_VOTE		F5	FF	-	-	-
*/
#define CLA_ACTION_WHITHOUT_DATA_INPUT 		0xF5

#define INS_PREPARE_BALLOT					0x00
#define INS_CREATE_CANDIDATE_ENCRYPTION		0x01
#define INS_CREATE_CGS97_CANDIDATE_PROOF	0x02
#define INS_CREATE_MP2_CANONICAL_VOTE		0xFF

/*
Instruction			CLA	INS	P1	P2		LC  	   		Data		LE		LE data
-------------------------------------------------------------------------------------
SELECT_CANDIDATE	F6	00	-	-	VOTE_CODE_LENGTH 	vote code 	1		rotation
*/

#define CLA_ACTION_WHITH_DATA_INPUT_AND_OUTPUT 	0xF6
#define INS_SELECT_CANDIDATE					0x00

/*
Instruction								CLA	INS	P1	P2		LC 	   								Data
----------------------------------------------------------------------------------------------------------------------------------------------
PREPARE_RECEIPT							F7	00	-	-	Q_LENGTH or ALPHA_BITS_BYTE_LENGTH		challenge
CREATE_MP2_CANONICAL_VOTE_WITH_HELP		F7	FF  XX	XX	P_LENGTH+Q_LENGTH						subtraction element || canonicalization factor   P1 = candidate index, P2 = chosen vector component (0 => X and 1 => Y)
*/
#define CLA_ACTION_WHITH_DATA_INPUT		 			0xF7

#define INS_PREPARE_RECEIPT							0x00
#define INS_CREATE_MP2_CANONICAL_VOTE_WITH_HELP		0xFF


/*###########################################################*
 * 						GET APDUS							 *
 *###########################################################*/

/*
Instruction						CLA	INS	P1	P2	LE
-----------------------------------------------------------------------------------
GET_PLEDGE		        		FA	00	-	-	Q_LENGTH or ALPHA_BITS_BYTE_LENGTH
GET_VCODE						FA	01	XX	-	Q_LENGTH or ALPHA_BITS_BYTE_LENGTH		P1 = candidate index
GET_VCODE_VALIDITY_FACTOR		FA	02	XX	XX	Q_LENGTH								P1 = candidate index, P2 = BMP index in MP1
*/
#define CLA_GET_RECEIPT_DATA				0xFA

#define INS_GET_PLEDGE						0x00
#define INS_GET_VCODE						0x01
#define INS_GET_VCODE_VALIDITY_FACTOR		0x02


/*
Instruction						CLA	INS	P1	P2	LE
----------------------------------------------------------
GET_CANDIDATE_ENCRYPTION_X 		FB	00	XX	XX	P_LENGTH	P1 = candidateIndex, P2 = ElGamalEncryption index
GET_CANDIDATE_ENCRYPTION_Y 		FB	01	XX	XX	P_LENGTH	P1 = candidateIndex, P2 = ElGamalEncryption index
*/
#define CLA_GET_CANDIDATE_ENCRYPTION		0xFB

#define INS_GET_CANDIDATE_ENCRYPTION_X		0x00
#define INS_GET_CANDIDATE_ENCRYPTION_Y		0x01


/*
Instruction		CLA	INS	P1	P2	LC  Data	LE
----------------------------------------------------
GET_CGS97 A1	FC	00	-	-	-	-		P_LENGTH
GET_CGS97 A2	FC	01	-	-	-	-		P_LENGTH
GET_CGS97 B1	FC	02  -	-	-	-		P_LENGTH
GET_CGS97 B2	FC	03  -	-	-	-		P_LENGTH
*/
#define CLA_GET_P_LENGTH_CANONICAL_VOTE_PROOF_DATA		0xFC

#define INS_GET_CGS97_A1        0x00
#define INS_GET_CGS97_A2        0x01
#define INS_GET_CGS97_B1        0x02
#define INS_GET_CGS97_B2        0x03


/*
Instruction						CLA	INS	P1	P2	LC  Data	LE
---------------------------------------------------------------------
GET_CGS97 C						FD	00	-	-	-	-		Q_LENGTH
GET_CGS97 D1					FD	01	-	-	-	-		Q_LENGTH
GET_CGS97 D2					FD	02	-	-	-	-		Q_LENGTH
GET_CGS97 R1					FD	03  -	-	-	-		Q_LENGTH
GET_CGS97 R2					FD	04	-	-	-	-		Q_LENGTH
GET_SUM_VALIDITY_FACTOR			FD	05	-	-	-	-		Q_LENGTH
GET_MP1A_BMP_CONFORMITY_PROOF 	FD	FF	-	-	-	-		Q_LENGTH
*/
#define CLA_GET_Q_LENGTH_CANONICAL_VOTE_PROOF_DATA		0xFD

#define INS_GET_CGS97_C         0x00
#define INS_GET_CGS97_D1        0x01
#define INS_GET_CGS97_D2        0x02
#define INS_GET_CGS97_R1        0x03
#define INS_GET_CGS97_R2        0x04

#define INS_GET_SUM_VALIDITY_FACTOR			0x05
#define INS_GET_MP1A_BMP_CONFORMITY_PROOF 	0xFF


/*
Instruction							CLA	INS	P1	P2	LC  Data	LE
---------------------------------------------------------------------
GET_VOTE_ENCRYPTION_SIGNATURE		FE	00	-	-	-	-		P_LENGTH
GET_VOTE_AND_RECEIPT_SIGNATURE		FE	01	-	-	-	-		P_LENGTH
GET_VOTE_HASH						FE	02	-	-	-	-		HASH_LENGTH
GET_VOTE_AND_RECEIPT_HASH			FE	03  -	-	-	-		HASH_LENGTH
*/
#define CLA_GET_HASH_AND_SIGNATURE			0xFE

#define INS_GET_VOTE_ENCRYPTION_SIGNATURE	0x00
#define INS_GET_VOTE_AND_RECEIPT_SIGNATURE	0x01
#define INS_GET_VOTE_HASH					0x02
#define INS_GET_VOTE_AND_RECEIPT_HASH		0x03



#endif /* MARKPLEDGEAPDUS_H_INCLUDE */
