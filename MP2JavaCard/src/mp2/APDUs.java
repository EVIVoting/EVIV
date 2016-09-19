package mp2;

public class APDUs {

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
	public static final byte CLA_SET_P_LENGTH 	=(byte)0xF0;

	public static final byte INS_SET_P			=(byte)0x00;
	public static final byte INS_SET_G			=(byte)0x01;
	public static final byte INS_SET_H			=(byte)0x02;
	public static final byte INS_SET_MP_G		=(byte)0x03;
	public static final byte INS_SET_MP_GINV	=(byte)0x04;

	/*
	Instruction				CLA	INS	P1	P2	LC  	   			Data
	---------------------------------------------------------------------------
	SET_Q	        		F1	00	-	-	Q_LENGTH	Q
	SET_MP2_GV_X			F1	01	-	-	Q_LENGTH	MP2 vector component X
	SET_MP2_GV_Y			F1	02	-	-	Q_LENGTH	MP2 vector component Y
	SET_LAMBDA_MULTIPLIER	F1	03	-	-	Q_LENGTH	MP2 lambda multiplier
	*/
	public static final byte CLA_SET_Q_LENGTH 			=(byte)0xF1;

	public static final byte INS_SET_Q					=(byte)0x00;
	public static final byte INS_SET_MP2_GV_X			=(byte)0x01;
	public static final byte INS_SET_MP2_GV_Y			=(byte)0x02;
	public static final byte INS_SET_LAMBDA_MULTIPLIER	=(byte)0x03;

	/*
	Instruction				CLA	INS	P1	P2	LC  	   				Data
	---------------------------------------------------------------------------
	SET_LAMBDA	       		F2	00	-	-	ALPHA_BITS_BYTE_LENGTH	MP2 lambda
	*/
	public static final byte CLA_SET_ALPHA_BITS_BYTE_LENGTH 	=(byte)0xF2;
	public static final byte INS_SET_LAMBDA						=(byte)0x00;

	/*
	Instruction				CLA	INS	P1		P2	LC	Data
	-----------------------------------------------------
	SET_ALPHA	       		F3	00	alpha	-	-	-
	*/
	public static final byte CLA_SET_VALUE_IN_P1P2 	=(byte)0xF3;
	public static final byte INS_SET_ALPHA			=(byte)0x00;



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
	public static final byte CLA_ACTION_WHITHOUT_DATA_INPUT		=(byte)0xF5;

	public static final byte INS_PREPARE_BALLOT					=(byte)0x00;
	public static final byte INS_CREATE_CANDIDATE_ENCRYPTION	=(byte)0x01;
	public static final byte INS_CREATE_CGS97_CANDIDATE_PROOF	=(byte)0x02;
	public static final byte INS_CREATE_MP2_CANONICAL_VOTE		=(byte)0xFF;

	/*
	Instruction			CLA	INS	P1	P2		LC  	   		Data		LE		LE data
	-------------------------------------------------------------------------------------
	SELECT_CANDIDATE	F6	00	-	-	VOTE_CODE_LENGTH 	vote code 	1		rotation
	*/

	public static final byte CLA_ACTION_WHITH_DATA_INPUT_AND_OUTPUT 	=(byte)0xF6;
	public static final byte INS_SELECT_CANDIDATE						=(byte)0x00;

	/*
	Instruction								CLA	INS	P1	P2		LC 	   								Data
	----------------------------------------------------------------------------------------------------------------------------------------------
	PREPARE_RECEIPT							F7	00	-	-	Q_LENGTH or ALPHA_BITS_BYTE_LENGTH		challenge
	CREATE_MP2_CANONICAL_VOTE_WITH_HELP		F7	FF  XX	XX	P_LENGTH+Q_LENGTH						subtraction element || canonicalization factor   P1 = candidate index, P2 = chosen vector component (0 => X and 1 => Y)
	*/
	public static final byte CLA_ACTION_WHITH_DATA_INPUT		 			=(byte)0xF7;

	public static final byte INS_PREPARE_RECEIPT							=(byte)0x00;
	public static final byte INS_CREATE_MP2_CANONICAL_VOTE_WITH_HELP		=(byte)0xFF;


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
	public static final byte CLA_GET_RECEIPT_DATA				=(byte)0xFA;

	public static final byte INS_GET_PLEDGE						=(byte)0x00;
	public static final byte INS_GET_VCODE						=(byte)0x01;
	public static final byte INS_GET_VCODE_VALIDITY_FACTOR		=(byte)0x02;


	/*
	Instruction						CLA	INS	P1	P2	LE
	----------------------------------------------------------
	GET_CANDIDATE_ENCRYPTION_X 		FB	00	XX	XX	P_LENGTH	P1 = candidateIndex, P2 = ElGamalEncryption index
	GET_CANDIDATE_ENCRYPTION_Y 		FB	01	XX	XX	P_LENGTH	P1 = candidateIndex, P2 = ElGamalEncryption index
	*/
	public static final byte CLA_GET_CANDIDATE_ENCRYPTION		=(byte)0xFB;

	public static final byte INS_GET_CANDIDATE_ENCRYPTION_X		=(byte)0x00;
	public static final byte INS_GET_CANDIDATE_ENCRYPTION_Y		=(byte)0x01;


	/*
	Instruction		CLA	INS	P1	P2	LC  Data	LE
	----------------------------------------------------
	GET_CGS97 A1	FC	00	-	-	-	-		P_LENGTH
	GET_CGS97 A2	FC	01	-	-	-	-		P_LENGTH
	GET_CGS97 B1	FC	02  -	-	-	-		P_LENGTH
	GET_CGS97 B2	FC	03  -	-	-	-		P_LENGTH
	*/
	public static final byte CLA_GET_P_LENGTH_CANONICAL_VOTE_PROOF_DATA		=(byte)0xFC;

	public static final byte INS_GET_CGS97_A1        =(byte)0x00;
	public static final byte INS_GET_CGS97_A2        =(byte)0x01;
	public static final byte INS_GET_CGS97_B1        =(byte)0x02;
	public static final byte INS_GET_CGS97_B2        =(byte)0x03;


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
	public static final byte CLA_GET_Q_LENGTH_CANONICAL_VOTE_PROOF_DATA		=(byte)0xFD;

	public static final byte INS_GET_CGS97_C         =(byte)0x00;
	public static final byte INS_GET_CGS97_D1        =(byte)0x01;
	public static final byte INS_GET_CGS97_D2        =(byte)0x02;
	public static final byte INS_GET_CGS97_R1        =(byte)0x03;
	public static final byte INS_GET_CGS97_R2        =(byte)0x04;

	public static final byte INS_GET_SUM_VALIDITY_FACTOR		=(byte)0x05;
	public static final byte INS_GET_MP1A_BMP_CONFORMITY_PROOF 	=(byte)0xFF;


	/*
	Instruction							CLA	INS	P1	P2	LC  Data	LE
	---------------------------------------------------------------------
	GET_VOTE_ENCRYPTION_SIGNATURE		FE	00	-	-	-	-		P_LENGTH
	GET_VOTE_AND_RECEIPT_SIGNATURE		FE	01	-	-	-	-		P_LENGTH
	GET_VOTE_HASH						FE	02	-	-	-	-		HASH_LENGTH
	GET_VOTE_AND_RECEIPT_HASH			FE	03  -	-	-	-		HASH_LENGTH
	*/
	public static final byte CLA_GET_HASH_AND_SIGNATURE			=(byte)0xFE;

	public static final byte INS_GET_VOTE_ENCRYPTION_SIGNATURE	=(byte)0x00;
	public static final byte INS_GET_VOTE_AND_RECEIPT_SIGNATURE	=(byte)0x01;
	public static final byte INS_GET_VOTE_HASH					=(byte)0x02;
	public static final byte INS_GET_VOTE_AND_RECEIPT_HASH		=(byte)0x03;

}
