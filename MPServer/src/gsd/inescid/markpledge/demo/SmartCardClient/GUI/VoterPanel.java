package gsd.inescid.markpledge.demo.SmartCardClient.GUI;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ActionListener;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.border.EtchedBorder;


public class VoterPanel extends JPanel {
	protected VoterData voters;
	protected RegistrarPanel registrar;
	protected VotePanel votePanel;
	
	
	
	protected boolean registrationOpen = false;
	protected boolean electionOpen = false;
	
	protected JScrollPane data;
	protected JScrollPane reg;
	protected JScrollPane cast;
	
	protected JSplitPane split;
	
	public VoterPanel(String[] candidates, ActionListener listener)
	{
		this.setBackground(Color.GREEN);
		this.setLayout(new BorderLayout());
		this.setMinimumSize(new Dimension(300,300));
		this.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.RAISED));
		
		JLabel label = new JLabel("Voter");
		
		label.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.LOWERED));
		label.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 25));
		label.setHorizontalAlignment(JLabel.CENTER);
		this.add(label,BorderLayout.NORTH);
		
		this.votePanel = new VotePanel(candidates, listener);
		this.cast = new JScrollPane(this.votePanel);
		this.cast.setMinimumSize(new Dimension(150,300));
		
		this.voters = new VoterData(this.votePanel);
		this.data = new JScrollPane(this.voters);
		this.data.setMinimumSize(new Dimension(150,300));
		
		this.registrar = new RegistrarPanel(listener);
		this.reg = new JScrollPane(this.registrar);
		this.reg.setMinimumSize(new Dimension(150,300));
						
		
						
		
		this.split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, 
				this.data, this.reg);
		this.split.setDividerSize(3);
		
		this.add(this.split,BorderLayout.CENTER);
		
	}

	public void startElectionandregistration(){
		this.electionOpen = true;
		this.registrationOpen = true;
		this.registrar.setReagistrationEnable(true);
		this.remove(this.split);
		this.split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, 
				this.data, this.reg);
		this.split.setDividerSize(3);
		this.add(this.split,BorderLayout.CENTER);
	}
	
	public void endRegistration(){
		this.registrationOpen = false;
		this.registrar.setReagistrationEnable(false);
		
		this.remove(this.split);
		this.split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, 
				this.data, this.cast);
		this.split.setDividerSize(3);
		this.add(this.split,BorderLayout.CENTER);
		this.votePanel.enableVote(true);
	}
	
	public void endElection(){
		this.electionOpen = false;
		
		this.votePanel.enableVote(false);
	}
	
	
	public void addCodeCard(int voterID, String codeCard)
	{
		this.voters.addCodeCard(voterID, codeCard);
	}
	
	public int addReceipt(String receipt)
	{
		return this.voters.addReceipt(receipt);
	}
	
	public int getSelectedCandidateIndex()
	{
		return this.votePanel.getSelectedCandidateIndex();
	}
	
	public int getSelectedVoterIndex()
	{
		return this.voters.getSelectedVoterIndex();
	}
	
	public void clear()
	{
		this.voters.clear();
	}
}
