package gsd.inescid.markpledge.interfaces;

import gsd.inescid.markpledge3.CGS97BallotValidity;

import java.math.BigInteger;

public interface IMPValidityProof {
	public CGS97BallotValidity[] getCanonicalVoteCGS97Proof();
	public BigInteger getVoteSumProof();
}
