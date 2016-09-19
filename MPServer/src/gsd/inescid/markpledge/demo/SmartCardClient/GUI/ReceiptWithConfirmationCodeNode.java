package gsd.inescid.markpledge.demo.SmartCardClient.GUI;

import gsd.inescid.markpledge.demo.SmartCardClient.GUI.treenodes.ReceiptNode;

public class ReceiptWithConfirmationCodeNode extends ReceiptNode {

	protected String ccode;
	public ReceiptWithConfirmationCodeNode(String text, String confirmationCode) {
		super(text);
		this.ccode = confirmationCode;
	}

}
