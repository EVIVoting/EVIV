package gsd.inescid.markpledge.demo.SmartCardClient.GUI;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.Rectangle;
import java.util.ArrayList;

import gsd.inescid.crypto.ElGamalPrivateKey;
import gsd.inescid.markpledge.MPUtil;
import gsd.inescid.markpledge.MarkPledgeType;
import gsd.inescid.markpledge.demo.SmartCardClient.GUI.treenodes.*;
import gsd.inescid.markpledge.interfaces.IMPEncryptedVote;
import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.interfaces.IMPReceipt;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;
import gsd.inescid.markpledge.interfaces.IMPVoteAndReceipt;

import javax.swing.JPanel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextPane;
import javax.swing.JTree;
import javax.swing.ScrollPaneConstants;
import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.event.TreeModelListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeSelectionModel;

public class BallotVoteReceiptListPanel extends JPanel implements TreeSelectionListener, TreeModelListener{

	private JTree voteTree;
	private DefaultTreeModel treeModel;
	private DefaultMutableTreeNode top;
	private JTextPane description;
	//private JScrollPane textPane;
	
	private ArrayList<VoteNode> votes = new ArrayList<VoteNode>();
	
	private MarkPledgeType ballotType;
	private IMPParameters param;
	
	public BallotVoteReceiptListPanel()
	{
		this.init();
	}
	public void init()
	{
		this.setLayout(new GridLayout(1,1));
		
		this.top = new DefaultMutableTreeNode("Votes");
		
		this.treeModel = new DefaultTreeModel(this.top);
		this.treeModel.addTreeModelListener(this);
		
		this.voteTree = new JTree(this.treeModel);
		this.voteTree.getSelectionModel().setSelectionMode(
				TreeSelectionModel.SINGLE_TREE_SELECTION);
		
		this.voteTree.addTreeSelectionListener(this);
		
		JScrollPane treeView = new JScrollPane(voteTree);
		treeView.setMinimumSize(new Dimension(150,100));
		
		
		this.description = new JTextPane();
		this.description.setEditable(false);
		JPanel aux = new JPanel(new BorderLayout());
		aux.add(this.description);
		JScrollPane textPane = new JScrollPane(aux);
		
		
		JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, 
								treeView, textPane);
		split.setDividerSize(3);
		
		
		this.add(split);
	}

	public void valueChanged(TreeSelectionEvent e) {
		Object node = this.voteTree.getLastSelectedPathComponent();
		
		if (node == null)
			return;
		
		if(node instanceof MPNode)
		{
			this.description.setText(((MPNode)node).getText());
			this.description.setCaretPosition(0);
			//this.textPane.getVerticalScrollBar().setValue(0);
			//System.out.println(((MPNode)node).getText());
		}
		else
		{
			this.description.setText("");
			//System.out.println(node.getClass().getName());
		}
		
	}
	
	
	public void addEncryptedVote(int voterID, IMPEncryptedVote vote)
	{
		VoteNode node = new VoteNode(voterID,vote);
		this.votes.add(node);
		this.treeModel.insertNodeInto(node, this.top, this.top.getChildCount());
		this.treeModel.reload();
		this.voteTree.setSelectionRow(voterID);
		this.voteTree.expandPath(this.voteTree.getSelectionPath());
		this.voteTree.setSelectionRow(voterID+1);

	}

	public void addReceiptAndValidity(int voterID, IMPReceipt receipt, 
			IMPValidityProof validity, String[] candidates)
	{
		VoteNode node = this.votes.get(voterID-1);
		node.update(voterID, receipt, validity, this.ballotType, this.param, candidates);
		
		this.treeModel.reload();
		this.voteTree.setSelectionRow(voterID);
		this.voteTree.expandPath(this.voteTree.getSelectionPath());
		this.voteTree.setSelectionRow(voterID+2);

	}
	
		
	public void setBallotTypeAndParameters(MarkPledgeType type, IMPParameters param)
	{
		this.ballotType = type;
		this.param = param;
	}
	
	public int[] getResults(ElGamalPrivateKey kpri)
	{
		int[] results = new int[4];
		for(VoteNode v : this.votes)
		{
			int[] rv = v.decryptVote(this.param, kpri);
			if(rv != null)
				for(int i=0; i<rv.length; i++)
					results[i] += rv[i];
		}
		return results;
	}
	
	
	public void treeNodesChanged(TreeModelEvent e) {
		// TODO Auto-generated method stub
	}

	public void treeNodesInserted(TreeModelEvent e) {
		// TODO Auto-generated method stub
	}

	public void treeNodesRemoved(TreeModelEvent e) {
		// TODO Auto-generated method stub
	}

	public void treeStructureChanged(TreeModelEvent e) {
		// TODO Auto-generated method stub
		
	}

	
}
