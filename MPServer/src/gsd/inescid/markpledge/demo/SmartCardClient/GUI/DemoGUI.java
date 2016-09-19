package gsd.inescid.markpledge.demo.SmartCardClient.GUI;

import gsd.inescid.crypto.ElGamalPrivateKey;
import gsd.inescid.markpledge.MPKeyAndParameters;
import gsd.inescid.markpledge.MPUtil;
import gsd.inescid.markpledge.MarkPledgeType;
import gsd.inescid.markpledge.interfaces.IMPEncryptedVote;
import gsd.inescid.markpledge.interfaces.IMPParameters;
import gsd.inescid.markpledge.interfaces.IMPReceipt;
import gsd.inescid.markpledge.interfaces.IMPValidityProof;
import gsd.inescid.markpledge.smartclient.CardConstants;
import gsd.inescid.markpledge.smartclient.CardUtil;
import gsd.inescid.markpledge.smartclient.connection.CardConnectionType;
import gsd.inescid.markpledge.smartclient.connection.CardException;
import gsd.inescid.markpledge.smartclient.connection.IMPCardConnection;
import gsd.inescid.markpledge.smartclient.connection.ISmartCardInterface;
import gsd.inescid.markpledge.smartclient.connection.MultosCOMCardInterface;
import gsd.inescid.markpledge.smartclient.connection.PCSimulatedCardConnection;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;

public class DemoGUI extends JFrame implements ActionListener{

	private String[] candidates = {"Alice   ", "Bob     ", "Charles ", "Dharma  "};
	private int votersCount = 0;
	
	private OptionsPanel options;
	private BulletinBoardPanel bulletinBoard;
	private VoterPanel voter;
	
	/**************************************************************/
	IMPParameters param;
	ElGamalPrivateKey kpri;
	MessageDigest MD;
	MarkPledgeType ballotType;
	BigInteger challenge;
	
	
	IMPCardConnection card;
	ISmartCardInterface cardInterface;
	ArrayList<PCSimulatedCardConnection> pcSimulators = new ArrayList<PCSimulatedCardConnection>();
	/**************************************************************/
	
	
	public DemoGUI(String title)
	{
		super(title);
		this.setDefaultCloseOperation(EXIT_ON_CLOSE);
		this.setLayout(new BorderLayout());
		
		this.options = new OptionsPanel();
		this.add(this.options, BorderLayout.EAST);
		
		this.bulletinBoard = new BulletinBoardPanel(this);
				
		this.voter = new VoterPanel(candidates, this);
		
		JScrollPane bb = new JScrollPane(this.bulletinBoard);
		bb.setMinimumSize(new Dimension(300,300));
		bb.setPreferredSize(new Dimension(450,600));
		
		JScrollPane v = new JScrollPane(this.voter);
		v.setMinimumSize(new Dimension(300,300));
		v.setPreferredSize(new Dimension(400,600));
		
		JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, v, bb);
		split.setDividerSize(3);
		this.add(split);
		
		
		/******************************/
		try {
			this.MD = MessageDigest.getInstance("SHA-1");
				
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		
		//this.setPreferredSize(new Dimension(800,600));
		this.pack();
		this.setVisible(true);
	}
	
	public static void main(String[] args)
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				new DemoGUI("EVIV and MarkPledge Demo Program");
			}
		});
	}
	
	
	public String[] getCandidates(){return this.candidates;}
	
	public void createElectioKeyPair()
	{
		this.voter.clear();
		this.votersCount = 0;
		this.pcSimulators = new ArrayList<PCSimulatedCardConnection>();

		final boolean SAME_GENERATOR = false;		
		final int P_LENGTH = 1024;
		final int ALPHA = 24;

		int qLength = this.options.getQLength();
		this.ballotType = this.options.getBallotType();

		MPKeyAndParameters keyAndParam;
		if(this.options.useStaticKey())
		{
			keyAndParam = MPUtil.generateStaticKeyAndParameters(P_LENGTH, qLength, ALPHA, ballotType, SAME_GENERATOR);
		} else
		{
			keyAndParam = MPUtil.generateKeyAndParameters(P_LENGTH, qLength, ALPHA, ballotType, SAME_GENERATOR);
		}

		this.param = keyAndParam.MP_PARAMETERS;
		this.param.setVoteCodeByteLength(CardConstants.CANDIDATE_CODE_LENGTH);

		this.kpri = keyAndParam.KEY_PAIR.privateKey;

		this.voter.startElectionandregistration();
		this.setVisible(false);
		this.setVisible(true);
	}

	public void createChallenge()
	{
		this.voter.endRegistration();
		this.challenge = MPUtil.createChallenge(this.param, this.ballotType);
		this.setVisible(false);
		this.setVisible(true);
	}
	
	public void closeElection()
	{
		this.voter.endElection();
		//return 	new int[]{2,7,3,9};
		
	}
		
	
	
	public boolean connectToCard(boolean toCastVote)
	{
		final boolean WITH_PERFORMANCE_TIMES = true;
		final boolean USE_SIMULATOR = false;
		final String CARD_READER = "OMNIKEY CardMan 3x21 0";
		//final byte[] AID = new byte[]{(byte)0xF0, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x02, (byte)0x04};
		final byte[] AID = new byte[]{(byte)0xF0, (byte)0x00, (byte)0x00, (byte)0x02};
		
		/**************************************************************/
		
		CardConnectionType cardConnectiontype = this.options.getCardConnectionType();

		try{
			switch (cardConnectiontype)
			{
			case CARD: 
				if(this.cardInterface!=null)
					this.cardInterface.close();
					
				// use multos card connection
				// create card connection
				this.cardInterface = new MultosCOMCardInterface(USE_SIMULATOR);
				// init card connection
				this.cardInterface.init(CARD_READER,AID);

				this.card = CardUtil.getCardConnection(this.param,
						this.ballotType, this.cardInterface, WITH_PERFORMANCE_TIMES);
				return true;

			case PC_SIM: // use PC simulation
				if(toCastVote)
				{
					int i = this.voter.getSelectedVoterIndex();
					if(i < 0)
						return false;
					this.card = this.pcSimulators.get(i);
				}
				else 
				{
					this.card = new PCSimulatedCardConnection(this.ballotType, this.param);
					this.pcSimulators.add((PCSimulatedCardConnection) this.card);
				}
				return true;
				
			default:
				System.out.println("ERROR in card connection selection");
				return false;
			}
		} catch (CardException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
	}

//	public void actionPerformed(ActionEvent e) {
//		try{
//			if (e.getActionCommand().equals("RegisterNewBallot"))
//			{
//				if(!connectToCard(false))
//					return;
//
//				this.votersCount++;
//				
//				/** STEP 1 - set parameters, create vote encryption and register ballot **/
//				IMPEncryptedVote encVote = 
//					card.setParametersAndCreateVoteEncryption(this.param, this.candidates.length);
//				this.bulletinBoard.addEncryptedVote(this.votersCount, encVote);
//
//				/** STEP 2 - get pledge and create code card**/
//				BigInteger pledge = card.getPledge();
//				this.voter.addCodeCard(this.votersCount, getCodeCard(pledge));
//				
//			} 
//			else if (e.getActionCommand().equals("CastVote"))
//			{
//				if(!connectToCard(true))
//					return;
//				
//				int selection = this.voter.getSelectedCandidateIndex();
//				if(selection <0)
//					return;
//
//				
//				/** STEP 3 - create and get receipt **/
//				//select candidate
//				BigInteger voteCode;
//				if(this.options.getCardConnectionType() == CardConnectionType.CARD)
//				{
//					byte[] aux = new byte[this.param.getVoteCodeByteLength()];
//					aux[0] = (byte)selection;
//					voteCode = new BigInteger(1,aux);
//				} else {
//					voteCode = BigInteger.valueOf(selection);
//				}
//				
//				
//				//get receipt
//				IMPReceipt receipt = card.getVoteReceipt(voteCode, this.challenge, 
//						this.candidates.length);
//				
//				/** STEP 4 - get canonical vote verification factors **/
//				IMPValidityProof validity = null;
//				//if (this.ballotType != MarkPledgeType.MP1)
//				validity = card.getValidity(this.candidates.length);
//				
//				int voterID = this.voter.addReceipt(getVoteReceipt(receipt.getVerificationCodes(), receipt.getRotation())); 
//				if(voterID > 0)
//				{
//					this.bulletinBoard.addReceiptAndValidity(voterID, receipt, validity);
//				}
//				
//			}
//		} catch(Exception ex)
//		{
//			ex.printStackTrace();
//		}
//	}

	
	private ActionEvent e;
	public void actionPerformed(ActionEvent e) 
	{
		if (e.getActionCommand().equals("RegisterNewBallot"))
		{
			registerBallot();
		}else if (e.getActionCommand().equals("CastVote")){
			castVote();	
		}

	}
	
	
	
	public void registerBallot()
	{
		try{
			if(!connectToCard(false))
				return;

			this.votersCount++;

			/** STEP 1 - set parameters, create vote encryption and register ballot **/
			IMPEncryptedVote encVote = 
				card.setParametersAndCreateVoteEncryption(this.param, this.candidates.length);
			this.bulletinBoard.addEncryptedVote(this.votersCount, encVote);

			/** STEP 2 - get pledge and create code card**/
			BigInteger pledge = card.getPledge();
			this.voter.addCodeCard(this.votersCount, getCodeCard(pledge));

		} catch(Exception ex)
		{
			ex.printStackTrace();
		}
	}	
		
	public void castVote()
	{
		try{
			if(!connectToCard(true))
				return;

			int selection = this.voter.getSelectedCandidateIndex();
			if(selection <0)
				return;


			/** STEP 3 - create and get receipt **/
			//select candidate
			BigInteger voteCode;
			if(this.options.getCardConnectionType() == CardConnectionType.CARD)
			{
				byte[] aux = new byte[this.param.getVoteCodeByteLength()];
				aux[0] = (byte)selection;
				voteCode = new BigInteger(1,aux);
			} else {
				voteCode = BigInteger.valueOf(selection);
			}


			//get receipt
			IMPReceipt receipt = card.getVoteReceipt(voteCode, this.challenge, 
					this.candidates.length);

			/** STEP 4 - get canonical vote verification factors **/
			IMPValidityProof validity = null;
			//if (this.ballotType != MarkPledgeType.MP1)
			validity = card.getValidity(this.candidates.length);

			int voterID = this.voter.addReceipt(getVoteReceipt(receipt.getVerificationCodes(), receipt.getRotation())); 
			if(voterID > 0)
			{
				this.bulletinBoard.addReceiptAndValidity(voterID, receipt, validity);
			}


		} catch(Exception ex)
		{
			ex.printStackTrace();
		}
	}
	
	public String getCodeCard(BigInteger pledge)
	{
		String s = "CODE CARD\n"+
				   "Alice  \t: -\n" +
				   "Bob    \t: -\n" +
				   "Charles\t: -\n" +
				   "Dharma \t: -\n" +
				   "----------------------------------\n" +
				   "Conf. Code\n" +
				   get3BytesToText(pledge);
		return s;
	}
	
	public static String getDecryptedVoteText(int[] results)
	{
		String s = "DECRYPTED VOTE\n"+
				   "Alice  \t: " + results[0] + "\n" +
				   "Bob    \t: " + results[1] + "\n" +
				   "Charles\t: " + results[2] + "\n" +
				   "Dharma \t: " + results[3] + "\n";
		return s;
	}
	
	public static String getVoteReceipt(BigInteger[] vcodes, int rotation)
	{
		BigInteger[] rvcodes = new BigInteger[vcodes.length];
		
		for(int i=0, k=rotation; i<vcodes.length; i++, k++)
		{
			k = k % vcodes.length;
			rvcodes[k] = vcodes[i];
		}
			
		String s = 	"\n###################\n\n" +
					"VOTE RECEIPT\n"+
					"Alice  \t: " + get3BytesToText(rvcodes[0]) + "\n" +
					"Bob    \t: " + get3BytesToText(rvcodes[1]) + "\n" +
					"Charles\t: " + get3BytesToText(rvcodes[2]) + "\n" +
					"Dharma \t: " + get3BytesToText(rvcodes[3]) + "\n";

		return s;
	}
	
	
	
	
	public static String get3BytesToText(BigInteger v)
	{
		byte[] aux = v.toByteArray();
		byte[] aux2 = new byte[3];
		System.arraycopy(aux, aux.length-3, aux2, 0, 3);
		BigInteger vf = new BigInteger(1,aux2);
		return vf.toString(16).toUpperCase();
	}
	
	
	public MarkPledgeType getBallotType()
	{
		return this.options.getBallotType();
	}
	
	public IMPParameters getElectionParameters()
	{
		return this.param;
	}
	
	public ElGamalPrivateKey getElectionPrivateKey()
	{
		return this.kpri;
	}
}


