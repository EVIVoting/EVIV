package gsd.inescid.markpledge.demo.SmartCardClient.GUI;

import gsd.inescid.markpledge.demo.SmartCardClient.GUI.treenodes.MPNode;
import gsd.inescid.markpledge.demo.SmartCardClient.GUI.treenodes.VoterNode;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextPane;
import javax.swing.JTree;
import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeSelectionModel;

public class VoterData extends JPanel implements TreeSelectionListener, TreeModelListener{

	private JTree voterTree;
	private DefaultTreeModel treeModel;
	private DefaultMutableTreeNode top;
	private JTextPane description;
	
	//private int votersCount;
	
	private int selectedVoterIndex;
	private VotePanel votePanel;
	
	public VoterData(VotePanel votePanel)
	{
		init(votePanel);
	}
	
	public void init(VotePanel votePanel){
		this.votePanel = votePanel;
		//this.votersCount = 1;
		
		this.setLayout(new GridLayout(1,1));
		this.setPreferredSize(new Dimension(100,450));
		
		this.top = new DefaultMutableTreeNode("Voters");
		this.treeModel = new DefaultTreeModel(this.top);
		this.treeModel.addTreeModelListener(this);
		
		this.voterTree = new JTree(this.treeModel);
		this.voterTree.getSelectionModel().setSelectionMode(
				TreeSelectionModel.SINGLE_TREE_SELECTION);
		
		this.voterTree.addTreeSelectionListener(this);
		
		JScrollPane treeView = new JScrollPane(voterTree);
		treeView.setMinimumSize(new Dimension(100,150));
		
		
		this.description = new JTextPane();
		this.description.setEditable(false);
		JPanel aux = new JPanel(new BorderLayout());
		aux.add(this.description);
		JScrollPane textPane = new JScrollPane(aux);
		textPane.setPreferredSize(new Dimension(100,300));
		
		
		JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, 
								treeView, textPane);
		split.setDividerSize(3);
		
		
		this.add(split);

	}

	
	
	public void addCodeCard(int voterID, String codeCard)
	{
		VoterNode voter = new VoterNode(voterID, codeCard);
		this.treeModel.insertNodeInto(voter, this.top, this.top.getChildCount());
		this.voterTree.setSelectionRow(voterID);
	}
	
	public int addReceipt(String receipt)
	{
		if (isVoterSelected())
		{
			VoterNode voter = (VoterNode) this.voterTree.getLastSelectedPathComponent();
			if(voter.addReceipt(receipt))
			{
				this.description.setText(voter.getText());
				return voter.getVoterID();
			}
		}
		return -1;
	}
	
	public boolean isVoterSelected()
	{
		Object node = this.voterTree.getLastSelectedPathComponent();
		
		if (node == null)
			return false;
		
		if(node instanceof VoterNode)
		{
			VoterNode n = (VoterNode) node; 
			//System.out.println("voter index:" +this.top.getIndex(n));
			this.selectedVoterIndex =this.top.getIndex(n);
			return true;
		}
		else
			return false;
	}
	
	
	public void valueChanged(TreeSelectionEvent arg0) {
		Object node = this.voterTree.getLastSelectedPathComponent();
		
		
		if (node == null)
			return;
		
		if(node instanceof MPNode)
		{
			MPNode n = (MPNode) node; 
			//System.out.println(this.top.getIndex(n));
			
			this.description.setText(n.getText());
			this.votePanel.clearSelection();
			//System.out.println(((MPNode)node).getText());
		}
		else
		{
			this.description.setText("");
			//System.out.println(node.getClass().getName());
		}
		
	}

	
	public int getSelectedVoterIndex()
	{
		if(isVoterSelected())
			return this.selectedVoterIndex;
		else
			return -1;
	}
	
	
	public void treeNodesChanged(TreeModelEvent arg0) {
		// TODO Auto-generated method stub
		
	}

	public void treeNodesInserted(TreeModelEvent arg0) {
		// TODO Auto-generated method stub
		this.voterTree.expandRow(0);
	}

	public void treeNodesRemoved(TreeModelEvent arg0) {
		// TODO Auto-generated method stub
		
	}

	public void treeStructureChanged(TreeModelEvent arg0) {
		// TODO Auto-generated method stub
		
	}
	
	public void clear()
	{
		this.removeAll();
		init(votePanel);
	}
	
}
