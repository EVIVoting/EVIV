package gsd.inescid.markpledge.demo.SmartCardClient.GUI;

import gsd.inescid.markpledge.MarkPledgeType;
import gsd.inescid.markpledge.smartclient.connection.CardConnectionType;

import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.border.EtchedBorder;


public class OptionsPanel extends JPanel implements ActionListener{

	private MPTypeRadioButton ballotType;
	private CardConnectionRadioButton connectionType;
	private int qSize;
	private JCheckBox staticKey;
	
	Dimension dim = new Dimension(100,100);
	
	public OptionsPanel()
	{
		this.setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
		this.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.RAISED));
		
		//this.setAlignmentX(LEFT_ALIGNMENT);
		JPanel p;
		p = new JPanel();
		//p.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.LOWERED));
		this.add(p);
		
		createMPOptionsPanel();
		p = new JPanel();
		//p.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.LOWERED));
		this.add(p);
		
		createCardConnectionOptionsPanel();
		p = new JPanel();
		//p.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.LOWERED));
		this.add(p);
		
		createParametersOptionsPanel();
		p = new JPanel();
		//p.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.LOWERED));
		this.add(p);
		

	}
	
	private void createMPOptionsPanel()
	{
		JPanel mpOptions = new JPanel();
		//mpOptions.setLayout(new BoxLayout(mpOptions, BoxLayout.Y_AXIS));
		mpOptions.setLayout(new GridLayout(4,1));
		
		mpOptions.setAlignmentX(LEFT_ALIGNMENT);
		//mpOptions.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.LOWERED));
		//mpOptions.setPreferredSize(dim);
		
		
		//Ballot type menu
		//mpOptions.add(new JLabel("  MP Type"));
		mpOptions.setBorder(BorderFactory.createTitledBorder("MarkPledge Type"));
		
		MPTypeRadioButton mp1 = new MPTypeRadioButton(MarkPledgeType.MP1);
		mp1.addActionListener(this);
		mpOptions.add(mp1);
		MPTypeRadioButton mp1a = new MPTypeRadioButton(MarkPledgeType.MP1A);
		mp1a.addActionListener(this);
		mpOptions.add(mp1a);
		MPTypeRadioButton mp2 = new MPTypeRadioButton(MarkPledgeType.MP2);
		mp2.addActionListener(this);
		mpOptions.add(mp2);
		MPTypeRadioButton mp3 = new MPTypeRadioButton(MarkPledgeType.MP3);
		mp3.addActionListener(this);
		mpOptions.add(mp3);
		
		ButtonGroup mp = new ButtonGroup();
		mp.add(mp1);
		mp.add(mp1a);
		mp.add(mp2);
		mp.add(mp3);
		mp3.setSelected(true);
		this.ballotType = mp3;
		
		this.add(mpOptions);
	}
	
	
	private void createCardConnectionOptionsPanel()
	{
		JPanel options = new JPanel();
		//options.setLayout(new BoxLayout(options, BoxLayout.Y_AXIS));
		options.setLayout(new GridLayout(2,1));
		options.setAlignmentX(LEFT_ALIGNMENT);
		//options.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.LOWERED));
		//options.setPreferredSize(dim);
		
		
		//Ballot type menu
		//options.add(new JLabel("Card Connection"));
		options.setBorder(BorderFactory.createTitledBorder("Card Connection"));
		
		CardConnectionRadioButton card = new CardConnectionRadioButton(CardConnectionType.CARD);
		card.addActionListener(this);
		options.add(card);
		CardConnectionRadioButton pc = new CardConnectionRadioButton(CardConnectionType.PC_SIM);
		pc.addActionListener(this);
		options.add(pc);
		
		
		ButtonGroup mp = new ButtonGroup();
		mp.add(card);
		mp.add(pc);
		pc.setSelected(true);
		this.connectionType = pc;
		
		this.add(options);
	}
	
	private void createParametersOptionsPanel()
	{
		JPanel options = new JPanel();
		//options.setLayout(new BoxLayout(options, BoxLayout.Y_AXIS));
		options.setLayout(new GridLayout(4,1));
		options.setAlignmentX(LEFT_ALIGNMENT);
		//options.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.LOWERED));
		//options.setPreferredSize(dim);
		
		
		//Ballot type menu
		options.setBorder(BorderFactory.createTitledBorder("Key Parameters"));
		
		JRadioButton q160 = new JRadioButton("|p|=1024 |q|=160");
		q160.setActionCommand("160");
		q160.addActionListener(this);
		options.add(q160);
		JRadioButton q512 = new JRadioButton("|p|=1024 |q|=512");
		q512.setActionCommand("512");
		q512.addActionListener(this);
		options.add(q512);
		
		ButtonGroup mp = new ButtonGroup();
		mp.add(q160);
		mp.add(q512);
		q160.setSelected(true);
		this.qSize = 160;
		
	
		options.add(new JPanel());
		this.staticKey = new JCheckBox("Use Static Key");
		this.staticKey.setSelected(true);
		options.add(this.staticKey);
		
		this.add(options);
	}
	
	
	public int getQLength()
	{
		return this.qSize;
	}
	
	public MarkPledgeType getBallotType()
	{
		return this.ballotType.getMPType();
	}
	
	public CardConnectionType getCardConnectionType()
	{
		return this.connectionType.getConnectionType();
	}
	
	public boolean useStaticKey()
	{
		return this.staticKey.isSelected();
	}
	
	public void actionPerformed(ActionEvent e) {
		
		if(e.getSource() instanceof MPTypeRadioButton)
			this.ballotType = (MPTypeRadioButton) e.getSource();
		else if (e.getSource() instanceof  CardConnectionRadioButton)
			this.connectionType = (CardConnectionRadioButton) e.getSource();
		else
			this.qSize = Integer.parseInt(e.getActionCommand());
		
		//System.out.println(e.getActionCommand());
	}
	
	
	
}
