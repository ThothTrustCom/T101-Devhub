package org.thothtrust.sc.certstore;

import javacard.framework.Shareable;

public interface CertStoreAPI extends Shareable {
	public boolean writeCert(byte ind, byte[] cert, short inOff, short storeOff, short len);
	
	public short readCert(byte ind, byte[] output, short outOff, short storeOff, short len);
	
	public void clearCert(byte ind);
	
	public short certLength(byte ind);
	
	public void resetAllCerts();
}
