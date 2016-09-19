package gsd.inescid.markpledge.demo.SmartCardClient.GUI;

import gsd.inescid.markpledge.MarkPledgeType;
import gsd.inescid.markpledge.interfaces.IMPEncryptedVote;
import gsd.inescid.markpledge.interfaces.IMPReceipt;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.MessageDigest;


import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.border.EtchedBorder;

public class BulletinBoardPanel extends JPanel implements ActionListener{

	private ElectionTallyPanel tallyPanel;
	private BallotVoteReceiptListPanel ballotPanel;
	
	private DemoGUI engine;
	
	
	JButton start, end, chal;
	
	
	public BulletinBoardPanel(DemoGUI engine)
	{
		this.engine = engine;
		this.init();
	}
	
	public void init()
	{
		this.setBackground(Color.CYAN);
		this.setLayout(new BorderLayout());
		this.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.RAISED));
		
		JLabel label = new JLabel("Bulletin Board");
		
		label.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.LOWERED));
		label.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 25));
		label.setHorizontalAlignment(JLabel.CENTER);
		this.add(label,BorderLayout.NORTH);
		
	
		JPanel actions = new JPanel();
		actions.setLayout(new GridLayout(1,2));
		this.start = new JButton("Start Election");
		this.start.setActionCommand("Start");
		this.start.addActionListener(this);
		this.start.setEnabled(true);
		actions.add(this.start);
		
		this.chal = new JButton("Create Challenge");
		this.chal.setActionCommand("Challenge");
		this.chal.addActionListener(this);
		this.chal.setEnabled(false);
		actions.add(this.chal);
		
		
		this.end = new JButton("Tally Votes");
		this.end.setActionCommand("End");
		this.end.addActionListener(this);
		this.end.setEnabled(false);
		actions.add(this.end);
		actions.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.LOWERED));
		this.add(actions,BorderLayout.SOUTH);
		
		
		/******************/
		JPanel mainPanel = new JPanel();
		//mainPanel.setLayout(new BoxLayout(mainPanel,BoxLayout.Y_AXIS));
		mainPanel.setLayout(new BorderLayout());
		
		this.tallyPanel = new ElectionTallyPanel(this.engine.getCandidates());
		mainPanel.add(this.tallyPanel, BorderLayout.NORTH);
		
		this.ballotPanel = new BallotVoteReceiptListPanel();
		mainPanel.add(this.ballotPanel);
				
		this.add(mainPanel);
		this.setPreferredSize(new Dimension(300,500));
		
	}

	
	public void actionPerformed(ActionEvent e) {
		//System.out.println(e.getActionCommand());
	
		if(e.getActionCommand().equals("Start"))
		{
			this.removeAll();
			this.init();
			
			this.start.setEnabled(false);
			engine.createElectioKeyPair();
			this.ballotPanel.setBallotTypeAndParameters(engine.getBallotType(), engine.getElectionParameters());
			this.chal.setEnabled(true);
			
		}
		else if(e.getActionCommand().equals("Challenge"))
		{	
			this.chal.setEnabled(false);
			engine.createChallenge();
			this.end.setEnabled(true);
		}
		else if(e.getActionCommand().equals("End"))
		{
			this.end.setEnabled(false);
			this.engine.closeElection();
			this.tallyPanel.setTally(this.ballotPanel.getResults(engine.getElectionPrivateKey()));
			this.start.setEnabled(true);
		}
		
	}
	
	
	public void addEncryptedVote(int voterID, IMPEncryptedVote vote)
	{
		this.ballotPanel.addEncryptedVote(voterID, vote);
	}

	public void addReceiptAndValidity(int voterID, IMPReceipt receipt, 
			IMPValidityProof validity)
	{
		this.ballotPanel.addReceiptAndValidity(voterID, receipt, validity, engine.getCandidates());
	}
	
}
