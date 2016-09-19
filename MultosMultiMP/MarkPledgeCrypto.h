#ifndef MARKPLEDGE_CRYPTO_H_INCLUDED
#define MARKPLEDGE_CRYPTO_H_INCLUDED

#include "DataStructures.h"

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
                                  unsigned char* r, ElGamalEncryption* result);


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
                                  unsigned char* r, ElGamalEncryption* result);

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
                                  unsigned char* r, ElGamalEncryption* result);


/**
 * Compute the challenge for the CGS97 proof by hashing the BE, A1, A2, B1 and B2 values.
 * IMPORTANT NOTE: for now only works for a challenge of length = 20 bytes = 160 bits.
 *
 */
void computeCGC97Challenge(unsigned char* c, unsigned char* digestData, unsigned char* q);

/**
 * Create the CGS97 ballot validity proof.
 INPUT
 * cryptParam: public cryptographic parameters
 * alpha: the random value used in the proof->be bit encryption
 * proof->be: the bit encryption
 * isYesVote: flag that indicates if the proof is for a YESvote (value 1) or for a NOvote (value 0)
 *
 OUTPUT
 * the CGS97 proof stored in the corresponding proof entries.
 */
void createCGS97Proof(ExponentialElGamalPublicKey* cryptoParam, unsigned char* alpha, 
	CGS97Proof* proof, int isYesVote);

/** Sum the canonical vote factors
INPUT
 * factors: the canonical vote encryption factors
 * numberOfCandidates: the number of candidates running in the election = number of canonical votes
 * modulusQ: the public key cryptographic modulus q
OUTPUT
 * fills the result array with the sum of the canonical vote factors
 */
 void createSumReceipt(CanonicalFactors* factors, unsigned char numberOfCandidates, 
	 unsigned char* result, unsigned char* modulusQ);


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

void transformToExponent(int yesVote, unsigned char* exponent, unsigned char* vectorIndex, 
	unsigned char* multiplier, unsigned char* q);

 
 

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
	MarkPledgeParameters* param, unsigned char numberOfCandidates);

void prepareBallotMP1A(VerificationCodes* verificationCodes, EncryptionFactors* encryptionFactors, 
	MarkPledgeParameters* param, unsigned char numberOfCandidates);

void prepareBallotMP2(VerificationCodes* verificationCodes, EncryptionFactors* encryptionFactors, 
	MarkPledgeParameters* param, unsigned char numberOfCandidates);

void prepareBallotMP3(VerificationCodes* verificationCodes, EncryptionFactors* encryptionFactors, 
	MarkPledgeParameters* param, unsigned char numberOfCandidates);

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
	MarkPledgeParameters* param, unsigned char isYesVote, unsigned char candidateIndex);

void createCandidateEncryptionMP1A(VerificationCodes* verificationCodes, 
	EncryptionFactors* encryptionFactors, VoteEncryption* voteEncryption, 
	MarkPledgeParameters* param, unsigned char isYesVote, unsigned char candidateIndex);

void createCandidateEncryptionMP2(VerificationCodes* verificationCodes, 
	EncryptionFactors* encryptionFactors, VoteEncryption* voteEncryption, 
	MarkPledgeParameters* param, unsigned char isYesVote, unsigned char candidateIndex);

void createCandidateEncryptionMP3(VerificationCodes* verificationCodes, 
	EncryptionFactors* encryptionFactors, VoteEncryption* voteEncryption, 
	MarkPledgeParameters* param, unsigned char isYesVote, unsigned char candidateIndex);

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
 void createReceiptMP1(VerificationCodes* verificationCodes, EncryptionFactors* encryptionFactors,
	 MarkPledgeParameters* param, unsigned char* chal, unsigned char yesVotePosition,
	 unsigned char numberOfCandidates);

 void createReceiptMP1A(VerificationCodes* verificationCodes, EncryptionFactors* encryptionFactors,
	 MarkPledgeParameters* param, unsigned char* chal, unsigned char yesVotePosition,
	 unsigned char numberOfCandidates);

 void createReceiptMP2(VerificationCodes* verificationCodes, EncryptionFactors* encryptionFactors,
	 MarkPledgeParameters* param, unsigned char* chal, unsigned char yesVotePosition,
	 unsigned char numberOfCandidates);

 void createReceiptMP3(VerificationCodes* verificationCodes, EncryptionFactors* encryptionFactors,
	 MarkPledgeParameters* param, unsigned char* chal, unsigned char yesVotePosition,
	 unsigned char numberOfCandidates);



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
 void createMP2CanonicalVote(MP2VoteEncryption* voteEncryption, VerificationCodes* verificationCodes,
	 EncryptionFactors* encryptionFactors, unsigned char* chal, MarkPledgeParameters* param, 
	 unsigned char numberOfCandidates, CanonicalVote* canonicalVote, CanonicalFactors* canonicalFactors);


 /*
  * Method to create the MP1 and MP1A BMP encryptions
  */
 void createBMPEncryptions(unsigned char* verificationCode, BMPEncryptionFactors* encryptionFactors[], BMP* BMPEncryptions[],
	MarkPledgeParameters* param, unsigned char isYesVote);

#endif // MARKPLEDGE_CRYPTO_H_INCLUDED
