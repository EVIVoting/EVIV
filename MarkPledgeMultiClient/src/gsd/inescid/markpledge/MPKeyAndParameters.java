package gsd.inescid.markpledge;

import gsd.inescid.crypto.ElGamalKeyPair;
import gsd.inescid.markpledge.interfaces.IMPParameters;

public class MPKeyAndParameters {
	public final IMPParameters MP_PARAMETERS;
	public final ElGamalKeyPair KEY_PAIR; 
	
	public MPKeyAndParameters(IMPParameters param, ElGamalKeyPair kpair) 
	{
		this.KEY_PAIR = kpair;
		this.MP_PARAMETERS = param;
	}
}
