package gsd.inescid.markpledge.demo.SmartCardClient.GUI;

import gsd.inescid.markpledge.MarkPledgeType;

import javax.swing.JRadioButton;

public class MPTypeRadioButton extends JRadioButton {

	MarkPledgeType type;
	
	public MPTypeRadioButton(MarkPledgeType type)
	{
		super(type.toString());
		this.type = type;
	}
	
	public MarkPledgeType getMPType()
	{
		return this.type;
	}
}
