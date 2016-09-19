package gsd.inescid.markpledge.smartclient.connection;



import com.jacob.activeX.ActiveXComponent;
import com.jacob.com.Variant;

import gsd.inescid.markpledge.smartclient.CardUtil;

public class MultosCOMCardInterface implements ISmartCardInterface {
	// Multos COM connection object reference
	private ActiveXComponent multosSDT;
	
	//Variant is the responsible to send and receive APDUs through the multosSDT
	private Variant v;
	
	//if true connects to the simulator, otherwise to the cardreader
	private boolean useSimulator; 
	
	public MultosCOMCardInterface(boolean useSimulator){
		//get COM object reference
		this.multosSDT = new ActiveXComponent("SmartDeck.Terminal");
		this.useSimulator = useSimulator;
	}
	
	
	
	public void init(String cardReader, byte[] applicationIdentifier) throws CardException {
		if(this.useSimulator)
		{
			//establish a connection to the simulator
			//the simulator must exist under the name "sim", ex: hsim appMP3MultosCard.hzx -ifd sim
			this.v = multosSDT.invoke("connectsim", "sim"); 
		} else {
			//establish a connection to the reader
			//this.v = multosSDT.invoke("connectpcsc", "OMNIKEY CardMan 3x21 0"); 
			//this.v = multosSDT.invoke("connectpcsc", "OMNIKEY CardMan 5x21 0");
			this.v = multosSDT.invoke("connectpcsc", cardReader);
		}
		
		//select applet
		//select the application
		//this.v = multosSDT.invoke("selectbyname", "math");
		//this.v = multosSDT.invoke("selectbyaid", "f0 00 00 02");
		//this.v = multosSDT.invoke("selectbyaid", "4d 79 4d 50 33 41 70 70 6c 65 74");
		this.v = multosSDT.invoke("selectbyaid", CardUtil.bytesToText(applicationIdentifier));
		
		
		this.v = multosSDT.invoke("getresponse");
		String reply = (String) this.v.toJavaObject();
		if (reply.startsWith("90"))
			System.out.println("Applet selected:" + reply);
		else
			throw new CardException(CardUtil.textToBytes(reply), null);
	}
	
	
	public byte[] sendReceiveAPDU(byte[] command) throws CardException
	{
		//set message
		v = multosSDT.invoke("setcommand", CardUtil.bytesToText(command));
		
		//send message
		v = multosSDT.invoke("exchange");
		
		//get simple response
		v = multosSDT.invoke("getresponse");
		String reply = (String) v.toJavaObject();
		reply = reply.trim();
		
		if(!reply.endsWith("90 00")) //an error occurred
			throw new CardException(CardUtil.textToBytes(reply), command);
		
		//strip reply code
		reply = reply.substring(0, reply.length() - 5);
		
		//System.out.println("Reply: " + reply);
		//System.out.println("Command: " + CardUtil.bytesToText(command));
		
		return CardUtil.textToBytes(reply);
	}

	public void close() throws CardException {}
	
}
