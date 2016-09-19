/*
 *
 *  Created on: 23 de Mai de 2011
 *      Author: Rui
 */

#ifndef DATA_STRUCTURES_H_INCLUDE
#define DATA_STRUCTURES_H_INCLUDE

#include "MarkPledgeConstants.h"

/* Exponential ElGamal public key */
typedef struct {
    unsigned char p[P_LENGTH]; /* p value (p criptographic modulus)*/
    unsigned char q[Q_LENGTH]; /* q value (q criptographic modulus and sub group order)*/
    unsigned char g[P_LENGTH]; /* Base generator */
    unsigned char h[P_LENGTH]; /* h = g^x is the public key, where x is the private key */
    unsigned char mpG[P_LENGTH]; /* Generator used to encode the message. It can be equal to g. */
    unsigned char mpGInv[P_LENGTH]; /* mpG ^ -1 */
} ExponentialElGamalPublicKey;

/* Matrix structure
    [a,b
     c,d] */
typedef struct{
    unsigned char a[Q_LENGTH];
    unsigned char b[Q_LENGTH];
    unsigned char c[Q_LENGTH];
    unsigned char d[Q_LENGTH];
} Matrix;

/*MP2 parameters*/
typedef struct {
    Matrix so2qGenerator; /* MP2 matrix generator (gamma) */
	unsigned char lambda [LAMBDA_LENGTH]; /* lambda */
    unsigned char lambdaMultiplier [Q_LENGTH]; /* lambda multiplier (includes the multiplication by 4, i.e. the real exponents of gamma are ((lambdaMultiplier * i) +- 1) */
	unsigned char lambdaTestMultiplier [Q_LENGTH]; /* lambda test multiplier (includes the multiplication by 2, i.e. the real test exponents of gamma are (lambdaTestMultiplier * i) */
} MP2Parameters;

/* structure to hold all MarkPledge parameters */
typedef struct {
	ExponentialElGamalPublicKey kpub;
	unsigned char alpha;
	MP2Parameters mp2Param;
} MarkPledgeParameters;

/* structure to support the vote and receipt hash computation */
typedef struct {
	unsigned char voteHash [HASH_LENGTH];
	unsigned char verificationCodesHash [HASH_LENGTH];
	unsigned char receiptValidityHash [HASH_LENGTH];
	unsigned char rotation;
	unsigned char challenge [Q_LENGTH]; //Max challenge length (MP3 = Q_LENGTH, MP1 and MP2 = MP1_AND_2_VERIFICATION_CODE_LENGTH
	unsigned char voteReceiptHash [HASH_LENGTH];
}VoteReceiptHashSupportStructure;


/* Exponential ElGamal Encryption */
typedef struct {
    unsigned char x[P_LENGTH]; /* g^r */
    unsigned char y[P_LENGTH]; /* h^r . g^m */
} ElGamalEncryption;


/* Ballot Mark Pair (BMP) for MP1 and MP1A*/
typedef struct {
	ElGamalEncryption left;
	ElGamalEncryption right;
} BMP;


/* MP1 vote  encryption structure */
typedef struct {
	BMP bmp [MAX_ALPHA];
	unsigned char hashChain [HASH_LENGTH];
}MP1VoteEncryption;


/* MP1A vote  encryption structure */
typedef struct {
	ElGamalEncryption canonicalVote;
	BMP bmp [MAX_ALPHA];
	unsigned char hashChain [HASH_LENGTH];
}MP1AVoteEncryption;


/* MP2 candidate Encryption */
typedef struct {
    ElGamalEncryption vectorComponentX;
    ElGamalEncryption vectorComponentY;
} MP2CandidateEncryption;

/* MP2 vote  encryption structure */
typedef struct {
	MP2CandidateEncryption candidateEncryption;
	unsigned char hashChain [HASH_LENGTH];
	MP2CandidateEncryption tempCandidateEncryption[MAX_CANDIDATES];
}MP2VoteEncryption;

/* MP3 candidate Encryption */
typedef struct {
    ElGamalEncryption be;
    ElGamalEncryption ccode;
} MP3CandidateEncryption;

/* MP3 vote  encryption structure */
typedef struct {
	MP3CandidateEncryption candidateEncryption;
	unsigned char hashChain [HASH_LENGTH];
}MP3VoteEncryption;


/* Vote Encryption Union*/
typedef union {
    MP1VoteEncryption mp1;
    MP1AVoteEncryption mp1A;
    MP2VoteEncryption mp2;
    MP3VoteEncryption mp3;
    ElGamalEncryption encryptions [1 + 2*MAX_ALPHA];
} VoteEncryptionUnion;

/* Vote Encryption structure */
typedef struct {
	VoteEncryptionUnion voteEncryption;
	VoteReceiptHashSupportStructure hashStructure;
}VoteEncryption;


/* canonical vote structure */
typedef struct {
	ElGamalEncryption candidateEncryption [MAX_CANDIDATES];
	unsigned char voteSumFactor [Q_LENGTH] ;
}CanonicalVote;


/* VerificationCodes
 * */
typedef union {
	unsigned char verificationCodeMP3[MAX_CANDIDATES][Q_LENGTH];
	unsigned char verificationCode[MAX_CANDIDATES][ALPHA_BITS_BYTE_LENGTH];
}VerificationCodes;



/* BMP encryption factors */
typedef struct {
	unsigned char left [Q_LENGTH];
	unsigned char right [Q_LENGTH];
} BMPEncryptionFactors;

/* MP1 candidate encryption factors */
typedef struct {
	BMPEncryptionFactors bmpFactor [MAX_ALPHA];
} MP1CandidateEncryptionFactors;

/* MP1A candidate encryption factors */
typedef struct {
	unsigned char canonicalVoteFactor [Q_LENGTH];
	BMPEncryptionFactors bmpFactor [MAX_ALPHA];
} MP1ACandidateEncryptionFactors;

/* MP2 candidate encryption factors */
typedef struct {
	unsigned char vectorComponentX [Q_LENGTH];
	unsigned char vectorComponentY [Q_LENGTH];
	unsigned char validityFactor [Q_LENGTH];
} MP2CandidateEncryptionFactors;

/* MP3 candidate encryption factors */
typedef struct {
	unsigned char be [Q_LENGTH];
	unsigned char ccode [Q_LENGTH];
	unsigned char validityFactor [Q_LENGTH];
} MP3CandidateEncryptionFactors;

/* Encryption factors */
typedef union {
	MP1CandidateEncryptionFactors mp1EncryptionFactors[MAX_CANDIDATES];
	MP1ACandidateEncryptionFactors mp1AEncryptionFactors[MAX_CANDIDATES];
	MP2CandidateEncryptionFactors mp2EncryptionFactors[MAX_CANDIDATES];
	MP3CandidateEncryptionFactors mp3EncryptionFactors[MAX_CANDIDATES];
}EncryptionFactors;

/* canonical vote factors */
typedef struct {
	unsigned char canonicalFactor[MAX_CANDIDATES][Q_LENGTH];
}CanonicalFactors;



/* CGS97 proof */
typedef struct {
    ElGamalEncryption canonicalVote;
    unsigned char a1[P_LENGTH];
    unsigned char a2[P_LENGTH];
    unsigned char b1[P_LENGTH];
    unsigned char b2[P_LENGTH];
    unsigned char c[Q_LENGTH];
    unsigned char d1[Q_LENGTH];
    unsigned char d2[Q_LENGTH];
    unsigned char r1[Q_LENGTH];
    unsigned char r2[Q_LENGTH];
} CGS97Proof;


/* shared vote encryption data structure */
typedef union{
	CGS97Proof cgs97Proof;
	VoteEncryption voteEncryption;
} SharedVoteEncryptionAndProofStructure;


/* MP2 Test vector*/
typedef struct {
	unsigned char x [Q_LENGTH];
	unsigned char y [Q_LENGTH];
} MP2Vector;

#endif /* DATA_STRUCTURES_H_INCLUDE */
