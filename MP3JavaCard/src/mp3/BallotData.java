package mp3;

public class BallotData {
	 short numberOfCandidates; 				/* number of candidates running in the current election */
	 short positionOfYesVote; 				/* position of the YESvote encryption <only for 1-out-of-n elections> */
	 short rotation; 						/* rotation necessary to align the YESvote to the selected candidate <only for 1-out-of-n elections>*/
	 byte[] chal; 							/* challenge value for the vote receipt */
	 CandidateVoteEncryptionData[] vote;	/* one position for each candidate */
	 byte[] voteSumFactor; 					/* encryption factor for the candidate vote sum verification */
	 
	 public BallotData() {
		 chal = new byte[MP3CardConstants.Q_LENGTH];
		 voteSumFactor = new byte[MP3CardConstants.Q_LENGTH];
		 vote = new CandidateVoteEncryptionData[MP3CardConstants.MAX_CANDIDATES];
		 for(short i=0; i<vote.length; i++)
			 vote[i] = new CandidateVoteEncryptionData();
	 }
	 
	
}
