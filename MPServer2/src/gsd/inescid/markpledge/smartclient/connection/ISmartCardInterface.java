package gsd.inescid.markpledge.smartclient.connection;

public interface ISmartCardInterface {
	public void init(String cardReader, byte[] applicationIdentifier) throws CardException;
	public void close() throws CardException;
	
	//to send the individual APDUs to the card
	public byte[] sendReceiveAPDU(byte[] command) throws CardException;
}
