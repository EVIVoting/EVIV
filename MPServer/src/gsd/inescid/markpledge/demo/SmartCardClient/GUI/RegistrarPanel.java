package gsd.inescid.markpledge.demo.SmartCardClient.GUI;

import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.event.ActionListener;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EtchedBorder;

public class RegistrarPanel extends JPanel {

	protected JButton register;
	
	public RegistrarPanel(ActionListener listener)
	{
		this.setLayout(new BorderLayout());
		
		JLabel label = new JLabel("Election Registration");
		label.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.LOWERED));
		label.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 16));
		label.setHorizontalAlignment(JLabel.CENTER);
		this.add(label,BorderLayout.NORTH);
		
		JLabel label2 = new JLabel("Register Ballot and Create Code Card");
		label2.setHorizontalAlignment(JLabel.CENTER);
		label2.setVerticalAlignment(JLabel.CENTER);
		this.add(label2);
		
		this.register = new JButton("Register New Ballot");
		this.register.setEnabled(false);
		this.register.setActionCommand("RegisterNewBallot");
		this.register.addActionListener(listener);
		this.add(this.register, BorderLayout.SOUTH);
	}
	
	public void setReagistrationEnable(boolean enable)
	{
		this.register.setEnabled(enable);
	}
}
