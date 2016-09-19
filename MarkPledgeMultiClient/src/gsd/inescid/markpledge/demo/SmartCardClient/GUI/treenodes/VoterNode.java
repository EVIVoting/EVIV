package gsd.inescid.markpledge.demo.SmartCardClient.GUI.treenodes;


public class VoterNode extends MPNode {

	protected boolean hasReceipt = false;
	
	int voterID;
	
	public VoterNode (int voterID, String codeCard)
	{
		super("Voter " + voterID, codeCard);
		this.voterID = voterID;
	}

	public boolean addReceipt(String receipt)
	{
		if(this.hasReceipt)
			return false;
		
		this.text = this.text + "\n----------------------------------\n" + receipt;
		this.hasReceipt = true;
		return true;
		
	}
	
	public int getVoterID()
	{
		return this.voterID;
	}
	
}