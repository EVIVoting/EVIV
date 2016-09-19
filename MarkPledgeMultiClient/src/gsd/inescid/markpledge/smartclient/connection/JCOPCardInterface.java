package gsd.inescid.markpledge.smartclient.connection;

import com.ibm.jc.*;
import com.ibm.jc.terminal.*;

public class JCOPCardInterface implements ISmartCardInterface {

	private JCTerminal terminal;
	private OPApplet applet;
	private boolean useSimulator;
	
	public JCOPCardInterface(boolean useSimulator)
	{
		this.useSimulator = useSimulator;
	}
	
	public void close() throws CardException {
		if (terminal != null)
			terminal.close();
	}

	public void init(String cardReader, byte[] applicationIdentifier) throws CardException {
		if(useSimulator){
			this.terminal = new RemoteJCTerminal();
			this.terminal.init("localhost:8050");
		} else {
			this.terminal = new PCSCJCTerminal();
			this.terminal.init(cardReader);
			//this.terminal.init("any|e");
		}
		this.terminal.open();
		JCard card = new JCard(this.terminal, null, 1000);
		this.applet = new OPApplet(card, applicationIdentifier, 0, applicationIdentifier.length);
		byte[] reply = applet.select();
		
		if(((reply[0] & 0xFF) == 0x90) && ((reply[1] & 0xFF) == 0))
			System.out.println("Applet selected.");
		else
			throw new CardException(reply, null);	
	}

	public byte[] sendReceiveAPDU(byte[] command) throws CardException {
		if(command.length==4)
		{
			byte[] aux = new byte[5];
			System.arraycopy(command, 0, aux, 0 , 4);
			command=aux;
		}
		byte[] reply = this.applet.send(command, 0, command.length);
		
		int replyLength = reply.length - 2;
		
		if(!(((reply[replyLength] & 0xFF) == 0x90) && ((reply[replyLength + 1] & 0xFF) == 0)))
			throw new CardException(reply, command);
			
		byte[] replyData = new byte[replyLength];
		System.arraycopy(reply, 0, replyData, 0, replyLength);
		return replyData;
	}

}
