package org.thothtrust.sc.certstore;
import javacard.framework.Shareable;
public interface CertStoreAPI extends Shareable {
boolean writeCert(byte param1, byte[] param2, short param3, short param4, short param5);
short readCert(byte param1, byte[] param2, short param3, short param4, short param5);
void clearCert(byte param1);
short certLength(byte param1);
void resetAllCerts();
}
