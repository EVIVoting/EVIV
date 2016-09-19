package gsd.inescid.markpledge.demo.SmartCardClient.GUI;

import java.awt.Font;
import java.awt.GridLayout;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;

public class ElectionTallyPanel extends JPanel {

	JLabel[] candidateLabel;
	
	public ElectionTallyPanel(String[] candidate)
	{
		this.setBorder(BorderFactory.createTitledBorder("Election Tally"));
		
		this.setLayout(new GridLayout(candidate.length,1));
		
		
		this.candidateLabel = new JLabel[candidate.length];
		for(int i=0; i<candidate.length; i++)
		{
			this.candidateLabel[i] = new JLabel(candidate[i] + ": -");
			this.candidateLabel[i].setFont(new Font(Font.MONOSPACED, Font.BOLD, 12));
			this.add(this.candidateLabel[i]);
		}
	}
	
	public void setTally(int[] tally)
	{
		for(int i=0; i<this.candidateLabel.length; i++)
		{
			String text = this.candidateLabel[i].getText();
			this.candidateLabel[i].setText(
					text.substring(0, text.length()-1) + tally[i]);
		}
	}
}
