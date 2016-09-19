package mp2;

public class CandidateVoteEncryptionData {

	 boolean yesVote; 		/* 1 if YESvote and 0 if NOvote */
	 byte[] beFactor; 		/* be random encryption factor */
	 byte[] ccode; 			/* ccode random value */
	 byte[] ccodeFactor; 	/* ccode random encryption factor */
	 byte[] vcode; 			/* vcode (verification code) value */
	 byte[] vcodeFactor; 	/* verification encryption factor for the vcode verification */
	 CandidateEncryption canonicalVote;

	 public CandidateVoteEncryptionData()
	 {
		 this.beFactor = new byte[MP3CardConstants.Q_LENGTH];
		 this.ccode = new byte[MP3CardConstants.Q_LENGTH]; 
		 this.ccodeFactor = new byte[MP3CardConstants.Q_LENGTH]; 
		 this.vcode = new byte[MP3CardConstants.Q_LENGTH]; 
		 this.vcodeFactor = new byte[MP3CardConstants.Q_LENGTH];
		 this.canonicalVote = new CandidateEncryption();
	 }
}
