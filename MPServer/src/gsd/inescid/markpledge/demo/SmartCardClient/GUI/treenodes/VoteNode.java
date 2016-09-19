package gsd.inescid.markpledge.demo.SmartCardClient.GUI.treenodes;

import gsd.inescid.crypto.ElGamalPrivateKey;
import gsd.inescid.markpledge.MPUtil;
import gsd.inescid.markpledge.MarkPledgeType;
import gsd.inescid.markpledge.demo.SmartCardClient.GUI.DemoGUI;
import gsd.inescid.markpledge.interfaces.IMPEncryptedVote;
import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.interfaces.IMPReceipt;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;
import gsd.inescid.markpledge.interfaces.IMPVoteAndReceipt;

import java.security.MessageDigest;


public class VoteNode extends MPNode {

	static MessageDigest MD;
	
	BallotNode ballot;
	ReceiptNode receipt;
	ValidityNode validity;
	DecryptedNode decryptedVote;
	
	IMPEncryptedVote voteEnc;
	IMPVoteAndReceipt voteAndReceipt;
	
	int voterID;
	boolean decryptVote = false;
	
	static{
		try{
			MD = MessageDigest.getInstance("SHA-1");
		}catch(Exception e)
		{
			e.printStackTrace();
		}
	}
	
	public VoteNode(String nodeName) {
		super(nodeName, nodeName);
	}

	public VoteNode(int voterID, IMPEncryptedVote vote)
	{
		super("Vote " + voterID, "Voter's " + voterID + " Vote");
		this.voterID = voterID;
		this.voteEnc = vote;
		init(vote);
	}
	
	
	public void init(IMPEncryptedVote vote)
	{
		this.ballot = new BallotNode("Ballot");
		this.ballot.text = vote.toString();
			
		this.receipt = new ReceiptNode("Receipt");
		this.receipt.text = "-";
		
		this.validity = new ValidityNode("Validity");
		this.validity.text = "-";
		
		this.decryptedVote = new DecryptedNode("Decrypted");
		this.decryptedVote.text = "-";
		
		
		this.add(ballot);
		this.add(receipt);
		this.add(validity);
		this.add(decryptedVote);
	}
	
	public boolean update(int voterID, IMPReceipt r, IMPValidityProof v, MarkPledgeType type,
			IMPParameters param, String[] candidates)
	{
		boolean valid = false;
		
		if(voterID != this.voterID)
		{
			System.out.println("ERROR: cannot set vote. VoterID does not match.");
			return false;
		}
		
			
		this.voteAndReceipt = MPUtil.getVoteAndReceipt(type, this.voteEnc, r, v);
		
		String m;
		//if (type != MarkPledgeType.MP1)
		{
			if(this.voteAndReceipt.verifyReceipt(param, MD))
			{
				m = "Receipt verification: OK\n";
				valid = true;
			}
			else
				m = "Receipt verification: FAIL\n";
			
			this.receipt.text = m + "\n" + r.toString(candidates);
		}
		//else
		//	this.validity.text = "Canonical candidates votes verification is not available.";
		this.receipt.text = DemoGUI.getVoteReceipt(r.getVerificationCodes(), r.getRotation()) +
							"\n###################\n\n" + this.receipt.text ;
		
		
		
		if (type != MarkPledgeType.MP1)
		{
			if(this.voteAndReceipt.verifyCanonicalVote(param, MD))
			{
				m = "Canonical candidate votes verification: OK\n";
				valid = valid && true;
			}
			else
				m = "Canonical candidate votes verification: FAIL\n";
			
			if(this.voteAndReceipt.verifyVoteSum(param, 1))
			{
				m += "One YESvote verification: OK\n";
				valid = valid && true;
			}
			else
				m += "One YESvote verification: FAIL\n";
		
			this.validity.text = m + "\n" + v.toString();
		}
		else
			this.validity.text = "Canonical candidates votes verification is not available.";
			
		this.decryptVote = valid;
		return valid;
	}
	
	
	public int[] decryptVote(IMPParameters param, ElGamalPrivateKey kpri)
	{
		if(this.decryptVote)
		{
			int[] results = MPUtil.decryptedCanonicalVote(voteAndReceipt.getCanonicalVote(param),
					kpri, param, this.voteAndReceipt.getVoteReceipt().getRotation());
			if(results != null)
				this.decryptedVote.text = DemoGUI.getDecryptedVoteText(results);
			else
				this.decryptedVote.text = "Vote Decryption ERROR";
			return results;
		}
		else
		{
			if(this.voteAndReceipt!=null)
				this.decryptedVote.text = "This vote failed the verifications.\nThe vote was NOT DECRYPTED.";
			else
				this.decryptedVote.text = "The voter did NOT CAST a vote.";
			return null;
		}
	}
	
	
}
