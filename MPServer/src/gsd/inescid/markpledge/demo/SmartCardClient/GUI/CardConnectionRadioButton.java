package gsd.inescid.markpledge.demo.SmartCardClient.GUI;

import gsd.inescid.markpledge.smartclient.connection.CardConnectionType;

import javax.swing.JRadioButton;

public class CardConnectionRadioButton extends JRadioButton {

	CardConnectionType type;
	
	public CardConnectionRadioButton(CardConnectionType type)
	{
		super(type.toString());
		this.type = type;
	}
	
	public CardConnectionType getConnectionType()
	{
		return this.type;
	}
}
