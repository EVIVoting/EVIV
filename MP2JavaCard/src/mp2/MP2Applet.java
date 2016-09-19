/**
 * 
 */
package mp2;


import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.APDU;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

/**
 * @author Rui Joaquim
 *
 */
public class MP2Applet extends Applet implements MP3CardConstants {
	public static final short ERR_COMMAND_NOT_ALLOWED         =(short)0x6900; /* used if an error occurs when checking the  APDU case */
	public static final short ERR_INVALID_CANDIDATE_SELECTION =(short)0x6901;
	public static final short ERR_ILLEGAL_STATE				  =(short)0x6902;	/* used when a command is out of the control sequence */
	public static final short ERR_WRONG_P1P2                  =(short)0x6B00;
	public static final short ERR_INS_NOT_SUPPORTED           =(short)0x6D00;
	public static final short ERR_CLA_NOT_SUPPORTED           =(short)0x6E00;
	public static final short ERR_NO_PRECISE_DIAGNOSTIC       =(short)0x6F00;
	public static final short ERR_WRONG_INPUT_LENGTH          =(short)0x6700;
	public static final short ERR_EXPECTED_P_LENGTH_OUTPUT    =(short)0x6C80;
	public static final short ERR_EXPECTED_Q_LENGTH_OUTPUT    =(short)0x6C40;
	public static final short ERR_EXPECTED_ONE_BYTE_OUTPUT    =(short)0x6C01;
	public static final short ERR_EXPECTED_ALPHA_BYTE_LENGTH  =(short)0x6C18;
	public static final short ERR_EXPECTED_HASH_LENGTH_OUTPUT =(short)0x6C20;
	
	private CandidateEncryption candidateEncXPTO;
	private CGS97Proof cgs97Proof;
	private BallotData ballot;
	private ElectionKeyParameters electionKey;
	
	/* Math buffers */
	private byte[] pBuffer1, pBuffer2, pBuffer3;
	private byte[] qBuffer1, qBuffer2, qBuffer3, qBuffer4;
	
	private Cipher rsaCipherP, rsaCipherPPow2, rsaCipherQPow2;
	private RSAPrivateKey exponentiationKey, keyPPow2, keyQPow2;
	private RandomData random;
	private MessageDigest digest;
	private byte[] digestOutput;
	
	private MP2Applet()
	{
		/* data initialization */
		//this.candidateEnc = new CandidateEncryption();
		this.cgs97Proof = new CGS97Proof();
		this.ballot = new BallotData();
		this.electionKey = new ElectionKeyParameters();
		
		/* Math buffers */
		this.pBuffer1 = JCSystem.makeTransientByteArray(P_LENGTH, JCSystem.CLEAR_ON_DESELECT);
		this.pBuffer2 = JCSystem.makeTransientByteArray(P_LENGTH, JCSystem.CLEAR_ON_DESELECT);
		this.pBuffer3 = JCSystem.makeTransientByteArray(P_LENGTH, JCSystem.CLEAR_ON_DESELECT);
		this.qBuffer1 = JCSystem.makeTransientByteArray(Q_LENGTH, JCSystem.CLEAR_ON_DESELECT);
		this.qBuffer2 = JCSystem.makeTransientByteArray(Q_LENGTH, JCSystem.CLEAR_ON_DESELECT);
		this.qBuffer3 = JCSystem.makeTransientByteArray(Q_LENGTH, JCSystem.CLEAR_ON_DESELECT);
		this.qBuffer4 = JCSystem.makeTransientByteArray(Q_LENGTH, JCSystem.CLEAR_ON_DESELECT);
		
		/* crypto objects */
		this.random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		this.digest = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM, false);
		this.digestOutput = JCSystem.makeTransientByteArray(digest.getLength(), JCSystem.CLEAR_ON_DESELECT);
		this.exponentiationKey = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, 
											(short)(P_LENGTH * 8), false);
		this.rsaCipherP = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
		this.rsaCipherPPow2 = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
		this.rsaCipherQPow2 = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

	}
	
	
	
	
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new MP2Applet()
				.register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	/**
	 * Reads the APDU buffer to an internal buffer.
	 * 
	 * @param apdu
	 * @param parameter the internal buffer
	 * @param parameterSize the data size
	 */
	private void setParameterFromAPDUBuffer(APDU apdu, byte[] parameter, short parameterSize)
	{
	  	
		byte[] buf = apdu.getBuffer();
		// Lc tells us the incoming apdu command length
		short receivedDataLength = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
		
		if(receivedDataLength != parameterSize)
			ISOException.throwIt(ERR_WRONG_INPUT_LENGTH);
				
		short readCount = apdu.setIncomingAndReceive();
		short paramIndex = 0;
		do
		{
			Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA , parameter, (short) paramIndex, readCount);
			paramIndex += readCount;
			readCount = apdu.receiveBytes ( ISO7816.OFFSET_CDATA );
		}while(paramIndex < parameterSize);

	}
	
	/**
	 * Send data. This method does not verify the expected response length.
	 * 
	 * @param apdu
	 * @param output the output data
	 */
	private void sendData(APDU apdu, byte[] output)
	{	
		byte[] buf = apdu.getBuffer();
		Util.arrayCopyNonAtomic(output, (short)0, buf, (short)0, (short)output.length);
		apdu.setOutgoingAndSend((short)0,(short)output.length);
	}
	
	/**
	 * Fill the dest array with random data that represents ans integer value less than this.q
	 * Requires: dest.length >= MP3VoteCreationCardInterface.Q_SIZE.
	 * @param dest 
	 * 		
	 */
	private void fillRandomBytesLessThanQ(byte[] dest)
	{
		this.random.generateData(this.qBuffer1, (short)0, (short)this.qBuffer1.length);
		while((this.electionKey.q[0] & MP3MathUti.BMASK) <= (this.qBuffer1[0] & MP3MathUti.BMASK))
		{
			this.random.generateData(this.qBuffer1, (short)0, (short)1);
		}
		Util.arrayCopyNonAtomic(this.qBuffer1, (short)0, dest, (short)0, (short)this.qBuffer1.length);
	}
	
	/**
	 * Initializes all data required to create the ballot encryption:
	 * 		1 - creates random commit codes
	 * 		2 - creates random encryption factors for be and commit
	 * 		3 - randomly selects the YESvote position
	 * 		4 - initializes the RSA cipher engines (for the squaring7multiplication function)
	 * 
	 * @param numberOfCandidates number of candidates in the ballot.
	 */
	private boolean initBallotCreation(byte numberOfCandidates){
		
		
		if(numberOfCandidates > MAX_CANDIDATES)
        	ISOException.throwIt(ERR_WRONG_P1P2);

        
        this.ballot.numberOfCandidates = numberOfCandidates;

        for(short i=0; i< this.ballot.numberOfCandidates; i++)
        {
        	//step 1 create commit code (ccode)
        	fillRandomBytesLessThanQ(this.ballot.vote[i].ccode);
        	
        	//step 2 create encryption factors
        	fillRandomBytesLessThanQ(this.ballot.vote[i].beFactor);
        	fillRandomBytesLessThanQ(this.ballot.vote[i].ccodeFactor);
		}

		//step 3 select YESvote position
        short s;
		do{
			this.random.generateData(this.qBuffer1, (short)0, (short)1);
			s = Util.makeShort((byte)0, this.qBuffer1[0]);
			s = (short)(s & MAX_CANDIDATES_FLAG);
		}while(s >= numberOfCandidates);
			
		this.ballot.positionOfYesVote = s;
		
		
		//step 4 initializes the RSA cipher engines (for the squaring7multiplication function)
		//step 4.1 init rsaCipherQPow2
		this.keyQPow2 = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, (short)(Q_LENGTH *8), false);
		this.keyQPow2.setModulus(this.electionKey.q, (short)0, Q_LENGTH);
		this.keyQPow2.setExponent(MP3MathUti.TWO, (short)0, (short)MP3MathUti.TWO.length);
		this.rsaCipherQPow2.init(keyQPow2, Cipher.MODE_ENCRYPT);
		
		//step 4.2 init rsaCipherPPow2
		this.keyPPow2 = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, (short)(P_LENGTH *8), false);
		this.keyPPow2.setModulus(this.electionKey.p, (short)0, P_LENGTH);
		this.keyPPow2.setExponent(MP3MathUti.TWO, (short)0, (short)MP3MathUti.TWO.length);
		this.rsaCipherPPow2.init(keyPPow2, Cipher.MODE_ENCRYPT);
		
		//step 4.3 init exponentiationKey modulus
		this.exponentiationKey.setModulus(this.electionKey.p, (short)0, P_LENGTH);
		
		return true;
	}
	
	/**
	 * Creates the vote receipt
	 * Requires: chal.length == q.length
	 * 			 chal < q
	 * @param chal the challenge to the vote encryption
	 */
	private void createReceipt(byte[] chal){
		byte[] ccode, vcode;
		
		// step 1 calculus of 2.chal
		MP3MathUti.addMod(chal, chal, this.qBuffer4, this.electionKey.q);

		// step 2 calculus of the vcodes and corresponding verification factors
		for(short i=(short)0; i < this.ballot.numberOfCandidates; i++)
		{
			// step 2.1 create the vcode
			if(i==this.ballot.positionOfYesVote)
			{
				vcode = this.ballot.vote[i].ccode;
			} 
			else //novotes 
			{	
				ccode = this.ballot.vote[i].ccode;
										//  2.chal	 -  ccode
				MP3MathUti.subtractMod(this.qBuffer4, ccode, this.qBuffer1, this.electionKey.q);
				vcode = this.qBuffer1;
			}
			// step 2.2 store the vcode
			Util.arrayCopyNonAtomic(vcode, (short)0, this.ballot.vote[i].vcode, (short)0, Q_LENGTH);
			// step 2.3 create the verification factor
			// step 2.3.1 chal-vcode
			MP3MathUti.subtractMod(chal, this.ballot.vote[i].vcode, this.qBuffer1, this.electionKey.q); 
			// step 2.3.2 (chal-vcode) * be encryption factor
			MP3MathUti.modMult(this.qBuffer1, this.ballot.vote[i].beFactor, this.electionKey.q, this.qBuffer2, this.qBuffer3, rsaCipherQPow2);
			// step 2.3.3 (chal-vcode) * be encryption factor + ccode encryption factor
			MP3MathUti.addMod(this.qBuffer2, this.ballot.vote[i].ccodeFactor, this.qBuffer3, this.electionKey.q);
			// step 2.4 store the verification factor
			Util.arrayCopyNonAtomic(this.qBuffer3, (short)0, this.ballot.vote[i].vcodeFactor, (short)0, (short)this.qBuffer3.length);
		}
	}
	
	/**
	 * Created the candidate vote ith encryption.
	 * Requires: 0 <= candidateIndex < this.numberOfCandidates.
	 * 
	 * @param candidateIndex
	 */
	private void createCandidateEncryption(short candidateIndex){
		
		byte[] message;
		boolean yesVote = candidateIndex == this.ballot.positionOfYesVote;
		CandidateEncryption candidateEnc = this.ballot.vote[candidateIndex].canonicalVote;
		
		// step 1 create be encryption
		message = yesVote ? this.electionKey.mp3G : this.electionKey.mp3GInv;
		elGamalEncryption(message, this.ballot.vote[candidateIndex].beFactor, candidateEnc.be.x, candidateEnc.be.y, this.pBuffer1, this.pBuffer2);
		
		// create ccode encryption 
		// create ccode message
		
		MP3MathUti.modPow(this.electionKey.mp3G, this.ballot.vote[candidateIndex].ccode, this.pBuffer1, this.exponentiationKey, this.rsaCipherP);
		message = this.pBuffer1;
		// ccode encryption
		elGamalEncryption(message, this.ballot.vote[candidateIndex].ccodeFactor, candidateEnc.ce.x, candidateEnc.ce.y, this.pBuffer2, this.pBuffer3);
		
	}
	
	/**
	 * Method to perform the Elgamal encryption of a message
	 * 
	 * @param message message to encrypt
	 * @param exponent the random exponent
	 * @param outputX g^exponent
	 * @param outputY h^exponent.message
	 * @param aux1 auxiliary buffer
	 * @param aux2 auxiliary buffer
	 */
	private void elGamalEncryption(byte[] message, byte[] exponent, byte[] outputX, byte[] outputY, byte[] aux1, byte[] aux2)
	{
		// step 1 - set exponent		
		this.exponentiationKey.setExponent(exponent, (short)0, (short)exponent.length);
		this.rsaCipherP.init(this.exponentiationKey, Cipher.MODE_ENCRYPT);
		
		// step 2 - X
		this.rsaCipherP.doFinal(this.electionKey.g, (short)0, (short)this.electionKey.g.length, aux1, (short)0);
		Util.arrayCopyNonAtomic(aux1, (short)0, outputX, (short)0, P_LENGTH);
		
		// step 3 - Y
		this.rsaCipherP.doFinal(this.electionKey.h, (short)0, P_LENGTH, aux1, (short)0);
		MP3MathUti.modMult(aux1, message, this.electionKey.p, aux1, aux2, this.rsaCipherPPow2);
		Util.arrayCopyNonAtomic(aux1, (short)0, outputY, (short)0, P_LENGTH);
		
	}

	/**
	 * Method to create the CGS97 candidate vote encryption (currently in this.candidateEnc) validity proof.
	 *  
	 * @param yesVote	candidate vote type
	 * @param alpha 	the random exponent used in the candidate vote encryption
	 */
	private void createCGS97ProofData(boolean yesVote, byte[] alpha){
		// w
		byte[] w;
		fillRandomBytesLessThanQ(this.qBuffer3);
		w = this.qBuffer3; 
		
		if(yesVote){
			// r1
			fillRandomBytesLessThanQ(this.cgs97Proof.r1); 
			// d1
			fillRandomBytesLessThanQ(this.cgs97Proof.d1);
			// a1
			MP3MathUti.modPow(this.electionKey.g, this.cgs97Proof.r1, this.pBuffer1, this.exponentiationKey, this.rsaCipherP);
			MP3MathUti.modPow(this.candidateEncXPTO.be.x, this.cgs97Proof.d1, this.pBuffer2, this.exponentiationKey, this.rsaCipherP);
			MP3MathUti.modMult(this.pBuffer1, this.pBuffer2, this.electionKey.p, this.pBuffer1, this.pBuffer3, this.rsaCipherPPow2);
			Util.arrayCopyNonAtomic(this.pBuffer1, (short)0, this.cgs97Proof.a1, (short)0, P_LENGTH);
			// b1
			MP3MathUti.modPow(this.electionKey.h, this.cgs97Proof.r1, this.pBuffer1, this.exponentiationKey, this.rsaCipherP);
			MP3MathUti.modMult(this.candidateEncXPTO.be.y, this.electionKey.mp3G, this.electionKey.p, this.pBuffer2, this.pBuffer3, this.rsaCipherPPow2);
			MP3MathUti.modPow(this.pBuffer2, this.cgs97Proof.d1, this.pBuffer2, this.exponentiationKey, this.rsaCipherP);
			MP3MathUti.modMult(this.pBuffer1, this.pBuffer2, this.electionKey.p, this.pBuffer1, this.pBuffer3, this.rsaCipherPPow2);
			Util.arrayCopyNonAtomic(this.pBuffer1, (short)0, this.cgs97Proof.b1, (short)0, P_LENGTH);
			// a2
			MP3MathUti.modPow(this.electionKey.g, w, this.pBuffer1, this.exponentiationKey, this.rsaCipherP);
			Util.arrayCopyNonAtomic(this.pBuffer1, (short)0, this.cgs97Proof.a2, (short)0, P_LENGTH);
			// b2
			MP3MathUti.modPow(this.electionKey.h, w, this.pBuffer1, this.exponentiationKey, this.rsaCipherP);
			Util.arrayCopyNonAtomic(this.pBuffer1, (short)0, this.cgs97Proof.b2, (short)0, P_LENGTH);
			// c
			calculateCGS97c();
			// d2
			MP3MathUti.subtractMod(this.cgs97Proof.c, this.cgs97Proof.d1, this.cgs97Proof.d2, this.electionKey.q);
			// r2
			MP3MathUti.modMult(alpha, this.cgs97Proof.d2, this.electionKey.q, this.qBuffer1, this.qBuffer2, this.rsaCipherQPow2);
			MP3MathUti.subtractMod(w, this.qBuffer1, this.cgs97Proof.r2, this.electionKey.q);
		} else {
			// r2
			fillRandomBytesLessThanQ(this.cgs97Proof.r2); 
			// d2
			fillRandomBytesLessThanQ(this.cgs97Proof.d2);
			// a1
			MP3MathUti.modPow(this.electionKey.g, w, this.pBuffer1, this.exponentiationKey, this.rsaCipherP);
			Util.arrayCopyNonAtomic(this.pBuffer1, (short)0, this.cgs97Proof.a1, (short)0, P_LENGTH);
			// b1
			MP3MathUti.modPow(this.electionKey.h, w, this.pBuffer1, this.exponentiationKey, this.rsaCipherP);
			Util.arrayCopyNonAtomic(this.pBuffer1, (short)0, this.cgs97Proof.b1, (short)0, P_LENGTH);
			// a2
			MP3MathUti.modPow(this.electionKey.g, this.cgs97Proof.r2, this.pBuffer1, this.exponentiationKey, this.rsaCipherP);
			MP3MathUti.modPow(this.candidateEncXPTO.be.x, this.cgs97Proof.d2, this.pBuffer2, this.exponentiationKey, this.rsaCipherP);
			MP3MathUti.modMult(this.pBuffer1, this.pBuffer2, this.electionKey.p, this.pBuffer1, this.pBuffer3, this.rsaCipherPPow2);
			Util.arrayCopyNonAtomic(this.pBuffer1, (short)0, this.cgs97Proof.a2, (short)0, P_LENGTH);
			// b2
			MP3MathUti.modPow(this.electionKey.h, this.cgs97Proof.r2, this.pBuffer1, this.exponentiationKey, this.rsaCipherP);
			MP3MathUti.modMult(this.candidateEncXPTO.be.y, this.electionKey.mp3GInv, this.electionKey.p, this.pBuffer2, this.pBuffer3, this.rsaCipherPPow2);
			MP3MathUti.modPow(this.pBuffer2, this.cgs97Proof.d2, this.pBuffer2, this.exponentiationKey, this.rsaCipherP);
			MP3MathUti.modMult(this.pBuffer1, this.pBuffer2, this.electionKey.p, this.pBuffer1, this.pBuffer3, this.rsaCipherPPow2);
			Util.arrayCopyNonAtomic(this.pBuffer1, (short)0, this.cgs97Proof.b2, (short)0, P_LENGTH);
			// c
			calculateCGS97c();
			// d1
			MP3MathUti.subtractMod(this.cgs97Proof.c, this.cgs97Proof.d2, this.cgs97Proof.d1, this.electionKey.q);
			// r2
			MP3MathUti.modMult(alpha, this.cgs97Proof.d1, this.electionKey.q, this.qBuffer1, this.qBuffer2, this.rsaCipherQPow2);
			MP3MathUti.subtractMod(w, this.qBuffer1, this.cgs97Proof.r1, this.electionKey.q);
		}
	}
	
	/**
	 * Method to create the challenge to the CGS97 proof.
	 * The challenge is the hash of be.x | be.y | a1 | a2 | b1 | b2
	 * 
	 *  If the length of the digest out put is less than the challenge length, then the reamining is filled with
	 *  multiple hashes of the original data.
	 *
	 */
	private void calculateCGS97c()
	{
		this.digest.reset();
		this.digest.update(this.candidateEncXPTO.be.x, (short)0, P_LENGTH);
		this.digest.update(this.candidateEncXPTO.be.y, (short)0, P_LENGTH);
		this.digest.update(this.cgs97Proof.a1, (short)0, P_LENGTH);
		this.digest.update(this.cgs97Proof.a2, (short)0, P_LENGTH);
		this.digest.update(this.cgs97Proof.b1, (short)0, P_LENGTH);
		this.digest.doFinal(this.cgs97Proof.b2, (short)0, P_LENGTH, this.digestOutput, (short)0);
		fillByteArrayByMultipleDigest(this.digestOutput, this.cgs97Proof.c);
	}
	
	/**
	 * This method return a pseudo-random value in Z_q by making multiple hashes of the originalData
	 * It uses the this.digest MessageDigest object and this.q.
	 * Requires: originalData.length == this.digest.getLength()
	 *  
	 * @param originalData base input data to the digest function. The originalData buffer is reused internally.
	 * @param output = output_0 || output_1 || output_2 ...
	 * 				   output_0 = originalData
	 * 				   output_i = digest(output_(i-1)) 
	 * 				
	 */
	private void fillByteArrayByMultipleDigest(byte[] originalData, byte[] output)
	{
		//
		//Algorithm
		short index = 0, hashIndex=0;
		byte[] lastHash = originalData; 
		
		//fill array with initial data 
		while(index < output.length && hashIndex < lastHash.length)
			output[index++] = lastHash[hashIndex++];			

		this.digest.reset();
		
		while(index < output.length)
		{			
			this.digest.doFinal(lastHash, (short)0, (short)lastHash.length, lastHash, (short)0);
			
			//fill array
			hashIndex = 0;
			while(index < output.length && hashIndex < lastHash.length)
				output[index++] = lastHash[hashIndex++];			
		}
		
		//adjust result to Z_q by shifting the high order byte bits of the result until a value less than q is achieved
		short outByte = (short)(output[0] & MP3MathUti.BMASK); //eliminate negative result from the 2's-complement representation
		short qByte = (short)(this.electionKey.q[0] & MP3MathUti.BMASK); //eliminate negative result from the 2's-complement representation
		while (outByte > qByte)
			outByte >>>= 1;
			
		output[0] = (byte)outByte;
	}
	
	/**
	 * This method computes the vote validity proof data, i.e.
	 * the sum of all be encryption factors mod q.
	 */
	private void computeVoteValidityProofData() 
	{	
		Util.arrayFillNonAtomic(this.ballot.voteSumFactor, (short)0, Q_LENGTH, (byte)0);
		for(short i=(short)0; i < this.ballot.numberOfCandidates; i++)
		{
			MP3MathUti.addMod(this.ballot.voteSumFactor, this.ballot.vote[i].beFactor, this.ballot.voteSumFactor, this.electionKey.q);
		}
	}
	
	
	
	/********************************************************************************
	 *			PROCESS APDU 														*
	 ********************************************************************************/
	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}
		byte[] buf = apdu.getBuffer();
		switch (buf[ISO7816.OFFSET_CLA]) {
		/*###########################################################*
		 * 						SET APDUS							 *
		 *###########################################################*/
			case APDUs.CLA_SET_P_LENGTH:
				switch(buf[ISO7816.OFFSET_INS])
				{
					case APDUs.INS_SET_P:
						setParameterFromAPDUBuffer(apdu, this.electionKey.p, P_LENGTH);
						break;
					case APDUs.INS_SET_G:
						setParameterFromAPDUBuffer(apdu, this.electionKey.g, P_LENGTH);
						break;
					case APDUs.INS_SET_H:
						setParameterFromAPDUBuffer(apdu, this.electionKey.h, P_LENGTH);
						break;
					case APDUs.INS_SET_MP_G:
						setParameterFromAPDUBuffer(apdu, this.electionKey.mp3G, P_LENGTH);
						break;
					case APDUs.INS_SET_MP_GINV:
						setParameterFromAPDUBuffer(apdu, this.electionKey.mp3GInv, P_LENGTH);
						break;
					default:
						ISOException.throwIt(ERR_INS_NOT_SUPPORTED);
				}
				return;

			case APDUs.CLA_SET_Q_LENGTH:
				switch(buf[ISO7816.OFFSET_INS])
				{
					case APDUs.INS_SET_Q:
						setParameterFromAPDUBuffer(apdu, this.electionKey.q, Q_LENGTH);
						break;
					case APDUs.INS_SET_MP2_GV_X:
						//memcpy(param.mp2Param.so2qGenerator.a, APDUdata.inputQ, Q_LENGTH);
						//memcpy(param.mp2Param.so2qGenerator.d, APDUdata.inputQ, Q_LENGTH);
						break;
					case APDUs.INS_SET_MP2_GV_Y:
						//memcpy(param.mp2Param.so2qGenerator.b, APDUdata.inputQ, Q_LENGTH);
						//SUBN(Q_LENGTH, param.mp2Param.so2qGenerator.c, param.kpub.q, param.mp2Param.so2qGenerator.b);
						break;
					case APDUs.INS_SET_LAMBDA_MULTIPLIER:
						//memcpy(param.mp2Param.lambdaMultiplier, APDUdata.inputQ, Q_LENGTH);
						//lambdaTestMultiplier = lambdaMultiplier / 2
						//memcpy(param.mp2Param.lambdaTestMultiplier, APDUdata.inputQ, Q_LENGTH);
						//ASSIGN_SHRN(Q_LENGTH, param.mp2Param.lambdaTestMultiplier, 1);
						break;
					default:
						ISOException.throwIt(ERR_INS_NOT_SUPPORTED);
				}
				return;

			case APDUs.CLA_SET_ALPHA_BITS_BYTE_LENGTH:
				switch(buf[ISO7816.OFFSET_INS])
				{
					case APDUs.INS_SET_LAMBDA:
						//memcpy(param.mp2Param.lambda, APDUdata.inputALPHA, LAMBDA_LENGTH);
						break;
					default:
						ISOException.throwIt(ERR_INS_NOT_SUPPORTED);
				}
				return;

			case APDUs.CLA_SET_VALUE_IN_P1P2:
				switch(buf[ISO7816.OFFSET_INS])
				{
					case APDUs.INS_SET_ALPHA:
						/*
						if (P1 > MAX_ALPHA)
							ISOException.throwIt(ERR_WRONG_P1P2);
						param.alpha = P1;*/
						break;
					default:
						ISOException.throwIt(ERR_INS_NOT_SUPPORTED);
				}
				return;

		/*###########################################################*
		 * 						ACTION APDUS						 *
		 *###########################################################*/

			case APDUs.CLA_ACTION_WHITHOUT_DATA_INPUT:
				switch(buf[ISO7816.OFFSET_INS])
				{
					case APDUs.INS_PREPARE_BALLOT:
						initBallotCreation(buf[ISO7816.OFFSET_P1]);
		                break;
		                
					case APDUs.INS_CREATE_CANDIDATE_ENCRYPTION:
						/* create be encryption */
		                createCandidateEncryption(buf[ISO7816.OFFSET_P1]);	
		                this.candidateEncXPTO = this.ballot.vote[buf[ISO7816.OFFSET_P1]].canonicalVote;
		                break;

					case APDUs.INS_CREATE_CGS97_CANDIDATE_PROOF:
						
						/* create CGS97 proof */
		            	boolean yesVote = buf[ISO7816.OFFSET_P1] == this.ballot.positionOfYesVote;
		            	this.candidateEncXPTO = this.ballot.vote[buf[ISO7816.OFFSET_P1]].canonicalVote;
		        		createCGS97ProofData(yesVote, this.ballot.vote[buf[ISO7816.OFFSET_P1]].beFactor);

						
						break;

					case APDUs.INS_CREATE_MP2_CANONICAL_VOTE:
						//TODO
						break;
					default:
						ISOException.throwIt(ERR_INS_NOT_SUPPORTED);
				}
				return;
				

			case APDUs.CLA_ACTION_WHITH_DATA_INPUT:
				switch(buf[ISO7816.OFFSET_INS])
				{
					case APDUs.INS_PREPARE_RECEIPT:
						setParameterFromAPDUBuffer(apdu, this.ballot.chal, Q_LENGTH);
		                createReceipt(this.ballot.chal);
						break;

					case APDUs.INS_CREATE_MP2_CANONICAL_VOTE_WITH_HELP:
						//TODO
					default:
						ISOException.throwIt(ERR_INS_NOT_SUPPORTED);
				}
				return;

			case APDUs.CLA_ACTION_WHITH_DATA_INPUT_AND_OUTPUT:
				switch(buf[ISO7816.OFFSET_INS])
				{
					case APDUs.INS_SELECT_CANDIDATE:
						
						/* get selected candidate */
						/** TODO: Translate vote code *
						for now the first byte representd the index of the selected candidate*/

						setParameterFromAPDUBuffer(apdu, this.qBuffer1, VOTE_CODE_LENGTH);
		            	if (this.qBuffer1[0] >= this.ballot.numberOfCandidates)
		            		ISOException.throwIt(ERR_INVALID_CANDIDATE_SELECTION);
		            	
		            	/* set rotation */
		            	byte r = (byte)(this.qBuffer1[0] - this.ballot.positionOfYesVote);
		        		if (r < 0)
		        			r += this.ballot.numberOfCandidates;
		            	this.ballot.rotation = (short) (r & MAX_CANDIDATES_FLAG);
		            	
		            	buf[0] = (byte) this.ballot.rotation;
		                apdu.setOutgoingAndSend((short)0,(short)1);
		                return;

					default:
						ISOException.throwIt(ERR_INS_NOT_SUPPORTED);
				}
				break;

		/*###########################################################*
		 * 						GET APDUS							 *
		 *###########################################################*/

			case APDUs.CLA_GET_RECEIPT_DATA:
				switch(buf[ISO7816.OFFSET_INS])
				{
					case APDUs.INS_GET_PLEDGE:
						// sendData(apdu, this.ballot.vote[ballot.positionOfYesVote].vectorX);
						 
						
						
						
						
						
						/*****************************************************************************/
						/*****************************************************************************/
						/***********************   MATRIX EXPONENTIATION TEST  ***********************/
						/*****************************************************************************/
						/*****************************************************************************/
						
						//Matrix mod pow test
						Matrix r = matrixTest();
						sendData(apdu, r.a);
						
						/*****************************************************************************/
						/*****************************************************************************/
						/*****************************************************************************/
						/*****************************************************************************/
							
						 return;
						 
						 
						 
						 
						 
						 
					case APDUs.INS_GET_VCODE:
						sendData(apdu, this.ballot.vote[buf[ISO7816.OFFSET_P1]].vcode);	
						return;

					case APDUs.INS_GET_VCODE_VALIDITY_FACTOR:
						sendData(apdu, this.ballot.vote[buf[ISO7816.OFFSET_P1]].vcodeFactor);	                
		                return;
		                
					default:
						ISOException.throwIt(ERR_INS_NOT_SUPPORTED);
				}
				return;

			case APDUs.CLA_GET_CANDIDATE_ENCRYPTION:
				switch(buf[ISO7816.OFFSET_INS])
				{
					case APDUs.INS_GET_CANDIDATE_ENCRYPTION_X:
						if(buf[ISO7816.OFFSET_P1] == 0)
							sendData(apdu, this.candidateEncXPTO.be.x);
						else
							sendData(apdu, this.candidateEncXPTO.ce.x);
						return;

					case APDUs.INS_GET_CANDIDATE_ENCRYPTION_Y:
						if(buf[ISO7816.OFFSET_P1] == 0)
							sendData(apdu, this.candidateEncXPTO.be.y);
						else
							sendData(apdu, this.candidateEncXPTO.ce.y);
						return;
						
					default:
						ISOException.throwIt(ERR_INS_NOT_SUPPORTED);
				}
				return;

			case APDUs.CLA_GET_P_LENGTH_CANONICAL_VOTE_PROOF_DATA:
				switch(buf[ISO7816.OFFSET_INS])
				{
					case APDUs.INS_GET_CGS97_A1:
						sendData(apdu, this.cgs97Proof.a1);
	                    return;

					case APDUs.INS_GET_CGS97_A2:
						sendData(apdu, this.cgs97Proof.a2);
	                    return;

					case APDUs.INS_GET_CGS97_B1:
						sendData(apdu, this.cgs97Proof.b1);
	                    return;
	                    
					case APDUs.INS_GET_CGS97_B2:
						sendData(apdu, this.cgs97Proof.b2);
	                    return;

					default:
						ISOException.throwIt(ERR_INS_NOT_SUPPORTED);
				}
				return;

			case APDUs.CLA_GET_Q_LENGTH_CANONICAL_VOTE_PROOF_DATA:
				switch(buf[ISO7816.OFFSET_INS])
				{
					case APDUs.INS_GET_CGS97_D1:
						sendData(apdu, this.cgs97Proof.d1);
	                    return;
	                    
					case APDUs.INS_GET_CGS97_D2:
						sendData(apdu, this.cgs97Proof.d2);
	                    return;

					case APDUs.INS_GET_CGS97_R1:
						sendData(apdu, this.cgs97Proof.r1);
	                    return;

					case APDUs.INS_GET_CGS97_R2:
						sendData(apdu, this.cgs97Proof.r2);
	                    return;

					case APDUs.INS_GET_CGS97_C:
						sendData(apdu, this.cgs97Proof.c);
						return;

					case APDUs.INS_GET_SUM_VALIDITY_FACTOR:
						/* calculate sum */
		            	computeVoteValidityProofData();
		            	sendData(apdu, this.ballot.voteSumFactor);
	                    return;

					case APDUs.INS_GET_MP1A_BMP_CONFORMITY_PROOF:
						//TODO
						// the bmp conformity factor is stored in the rigth position
						//memcpy(APDUdata.outputQ, encryptionFactors.mp1AEncryptionFactors[P1].bmpFactor[P2].right, Q_LENGTH);
						//ExitLa(Q_LENGTH);
						return;

					default:
						ISOException.throwIt(ERR_INS_NOT_SUPPORTED);
				}
				return;

			case APDUs.CLA_GET_HASH_AND_SIGNATURE:
				switch(buf[ISO7816.OFFSET_INS])
				{
					case APDUs.INS_GET_VOTE_ENCRYPTION_SIGNATURE:
						//TODO
					case APDUs.INS_GET_VOTE_AND_RECEIPT_SIGNATURE:
						//TODO
					case APDUs.INS_GET_VOTE_HASH:
						//TODO
					case APDUs.INS_GET_VOTE_AND_RECEIPT_HASH:
						//TODO
						return;
						
					default:
						ISOException.throwIt(ERR_INS_NOT_SUPPORTED);
				}
				return;

		
		
		
		
		
		default:
			ISOException.throwIt(ERR_CLA_NOT_SUPPORTED);
	  }

	    /* This should not happen */
		ISOException.throwIt(ERR_NO_PRECISE_DIAGNOSTIC);
	}

	/*************************************************************************************/
	/**				TEST MATRIX EXP **/
	/**************************************************************************************/
		private void matrixModMultSO2Q(Matrix ma, Matrix mb, Matrix mr, byte[] mod, Cipher rsaCipher, byte[] ri1, byte[]ri2, byte[] aux)
		{	
			//byte[] ri1 = new byte[Q_LENGTH]; 
			//byte[] ri2 = new byte[Q_LENGTH]; 
			//byte[] aux = new byte[Q_LENGTH];
			
			/** mrA */
			MP3MathUti.modMult(ma.a, mb.a, mod, ri1, aux, rsaCipher);
			MP3MathUti.modMult(ma.b, mb.c, mod, ri2, aux, rsaCipher);
			MP3MathUti.addMod(ri1, ri2 , mr.a, mod);
			/** mrD */
			Util.arrayCopyNonAtomic(mr.a, (short)0, mr.d, (short)0, Q_LENGTH);
			
			/** mrB */
			MP3MathUti.modMult(ma.a, mb.b, mod, ri1, aux, rsaCipher);
			MP3MathUti.modMult(ma.b, mb.d, mod, ri2, aux, rsaCipher);
			MP3MathUti.addMod(ri1, ri2 , mr.b, mod);
			
			/** mrC */
			MP3MathUti.subtract(mod, mr.b, mr.c);
				
		}
		
		private Matrix matrixModExp(Matrix m, byte[] exp, byte[] mod, Cipher rsaCipher)
		{
			Matrix mr = new Matrix(Q_LENGTH); 
			Matrix mAux = new Matrix(Q_LENGTH);
			Matrix ma = new Matrix(Q_LENGTH);
			Matrix temp;
			
			byte[] exponent = new byte[exp.length];
			byte iExponentByte = (byte)(exp.length - 1);
			byte iExponentBit = 0;
			short auxByte;// = (short)(exponent[iExponentByte] & 0xFF);
			
			Util.arrayCopyNonAtomic(exp, (short)0, exponent, (short)0, (short)exp.length);
			auxByte = (short)(exponent[iExponentByte] & 0xFF);
			
			Util.arrayCopyNonAtomic(m.a, (short)0, ma.a, (short)0, Q_LENGTH);
			Util.arrayCopyNonAtomic(m.b, (short)0, ma.b, (short)0, Q_LENGTH);
			Util.arrayCopyNonAtomic(m.c, (short)0, ma.c, (short)0, Q_LENGTH);
			Util.arrayCopyNonAtomic(m.d, (short)0, ma.d, (short)0, Q_LENGTH);

			
			if((auxByte & 0x01) == 1)
			{
				Util.arrayCopyNonAtomic(ma.a, (short)0, mr.a, (short)0, Q_LENGTH);
				Util.arrayCopyNonAtomic(ma.b, (short)0, mr.b, (short)0, Q_LENGTH);
				Util.arrayCopyNonAtomic(ma.c, (short)0, mr.c, (short)0, Q_LENGTH);
				Util.arrayCopyNonAtomic(ma.d, (short)0, mr.d, (short)0, Q_LENGTH);
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
				
				
				matrixModMultSO2Q(ma, ma, mAux, mod, rsaCipher, this.qBuffer1, this.qBuffer2, this.qBuffer3);
				temp = ma;
				ma = mAux;
				mAux = temp;
				
				if((auxByte & 0x01) == 1)
				{
					matrixModMultSO2Q(ma, mr, mAux, mod, rsaCipher, this.qBuffer1, this.qBuffer2, this.qBuffer3);
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
		
		
		private boolean isZero(byte[] v)
		{
			for(short i=(short)(v.length-1); i>=0; i--)
				if(v[i]!=0)
					return false;
			return true;
		}
		
		
		private Matrix matrixTest()
		{
			Matrix ma = new Matrix(Q_LENGTH);
			byte[] exponent = new byte[Q_LENGTH];
			
			Util.arrayCopyNonAtomic(this.electionKey.p, (short)0, ma.a, (short)0, (short)Q_LENGTH);
			ma.a[0] = 3;
			Util.arrayCopyNonAtomic(this.electionKey.p, (short)this.electionKey.q.length, ma.b, (short)0, (short)Q_LENGTH);
			ma.b[0] = 3;
			MP3MathUti.subtractMod(this.electionKey.q, ma.b, ma.c, this.electionKey.q);
			Util.arrayCopyNonAtomic(ma.a, (short)0, ma.d, (short)0, (short)Q_LENGTH);
			
			Util.arrayCopyNonAtomic(this.electionKey.g, (short)0, exponent, (short)0, (short)Q_LENGTH);
			
			//Matrix mr = new Matrix(Q_LENGTH);
			return matrixModExp(ma, exponent, this.electionKey.q, this.rsaCipherQPow2);
			//Util.arrayCopyNonAtomic(mr.a, (short)0, this.qBuffer1, (short)0, (short)Q_LENGTH);
		}
		
	/**************************************************************************************/
	
	
}