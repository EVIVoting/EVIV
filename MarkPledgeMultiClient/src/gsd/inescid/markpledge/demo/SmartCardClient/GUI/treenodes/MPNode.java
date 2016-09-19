package gsd.inescid.markpledge.demo.SmartCardClient.GUI.treenodes;

import javax.swing.tree.DefaultMutableTreeNode;

public class MPNode extends DefaultMutableTreeNode {

	protected String text;
	
	public MPNode (String nodeName, String text)
	{
		super(nodeName);
		this.text = text;
	}
	
	public String getText()
	{
		return this.text;
	}
}
