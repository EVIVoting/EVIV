package gsd.inescid.markpledge.demo.SmartCardClient.GUI;

import gsd.inescid.markpledge.MarkPledgeType;

import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionListener;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EtchedBorder;

public class VotePanel extends JPanel {

	protected JButton cast;
	protected JCheckBox[] selection;
	protected ButtonGroup group;
	
	public VotePanel(String[] candidates, ActionListener listener)
	{	
		this.setLayout(new BorderLayout());
		
		JLabel label = new JLabel("Vote Casting");
		label.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.LOWERED));
		label.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 16));
		label.setHorizontalAlignment(JLabel.CENTER);
		this.add(label,BorderLayout.NORTH);

		
		
		
		JPanel options = new JPanel();
		options.setLayout(new GridLayout(4,1));
		
		options.setAlignmentX(LEFT_ALIGNMENT);
		options.setBorder(BorderFactory.createTitledBorder("Ballot"));
		group = new ButtonGroup();
	
		this.selection = new JCheckBox[candidates.length];
		for(int i=0; i<candidates.length; i++)
		{
			JCheckBox c = new JCheckBox(candidates[i]);
			c.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 20));
			
			options.add(c);
			group.add(c);
			this.selection[i]=c;
		}	
		
		
		JPanel aux = new JPanel(new GridLayout(3,1));
		aux.add(new JPanel());
		aux.add(options);
		aux.add(new JPanel());
		
				
		this.add(aux);
		
		this.cast = new JButton("Cast Vote");
		this.cast.setActionCommand("CastVote");
		this.cast.setEnabled(false);
		this.cast.addActionListener(listener);
		this.add(this.cast, BorderLayout.SOUTH);
	}
	
	public void enableVote(boolean enable)
	{
		this.cast.setEnabled(enable);
	}
	
	public int getSelectedCandidateIndex()
	{
		for(int i=0; i<this.selection.length; i++)
			if (this.selection[i].isSelected())
			{
				return i;
			}
		return -1;
	}
	
	public void clearSelection()
	{
		this.group.clearSelection();
	}
}
