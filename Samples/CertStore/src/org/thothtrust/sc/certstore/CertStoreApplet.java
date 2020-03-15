package org.thothtrust.sc.certstore;

import javacard.framework.*;

/**
 * Certificate Store.
 * 
 * @author ThothTrust Pte Ltd.
 */
public class CertStoreApplet extends Applet implements CertStoreAPI {

	private byte[] clientAIDBytes = { 
			(byte) 0xD2, (byte) 0x76, (byte) 0x00, (byte) 0x01, (byte) 0x24, (byte) 0x01, (byte) 0x03, (byte) 0x03, 
			(byte) 0xAF, (byte) 0xAF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
	public static final short MAX_CERT_SIZE = (short) 1152;
	public short cert1Len = 0;
	public short cert2Len = 0;
	public short cert3Len = 0;
	public short cert4Len = 0;
	public static byte[] cert1 = new byte[MAX_CERT_SIZE];
	public static byte[] cert2 = new byte[MAX_CERT_SIZE];
	public static byte[] cert3 = new byte[MAX_CERT_SIZE];
	public static byte[] cert4 = new byte[MAX_CERT_SIZE];

	public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
		if (clientAID.equals(clientAIDBytes, (short) 0, (byte) (clientAIDBytes.length & 0xFF))) {
			return (CertStoreAPI) this;
		}

		return null;
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new CertStoreApplet();
	}

	protected CertStoreApplet() {
		register();
	}

	public void process(APDU apdu) {
		if (selectingApplet()) {
			return;
		}

		ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
	}

	public boolean writeCert(byte ind, byte[] input, short inOff, short storeOff, short len) {
		// Allows writing to portions of certificate store
		if (doCertIOByIndicator(ind, true, input, inOff, storeOff, len) == len) {
			return true;
		}
		return false;
	}

	public short readCert(byte ind, byte[] output, short outOff, short storeOff, short len) {
		// Allows reading from portions of certificate store
		return doCertIOByIndicator(ind, false, output, outOff, storeOff, len);
	}

	public void clearCert(byte ind) {
		clearCertByIndicator(ind);
	}

	public short certLength(byte ind) {
		return getCertLengthByIndicator(ind);
	}

	private short getCertLengthByIndicator(byte ind) {
		switch (ind) {
		case (byte) 0x00:
			// SIG Cert
			return cert1Len;
		case (byte) 0x01:
			// DEC Cert
			return cert2Len;
		case (byte) 0x02:
			// AUT Cert
			return cert3Len;
		case (byte) 0xFF:
			// SM Cert
			return cert4Len;
		default:
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		}
		return (short) -1;
	}

	private void clearCertByIndicator(byte ind) {
		switch (ind) {
		case (byte) 0x00:
			// SIG Cert
			JCSystem.beginTransaction();
			Util.arrayFillNonAtomic(cert1, (short) 0, (short) cert1.length, (byte) 0x00);
			cert1Len = (short) 0;
			JCSystem.commitTransaction();
			return;
		case (byte) 0x01:
			// DEC Cert
			JCSystem.beginTransaction();
			Util.arrayFillNonAtomic(cert2, (short) 0, (short) cert2.length, (byte) 0x00);
			cert2Len = (short) 0;
			JCSystem.commitTransaction();
			return;
		case (byte) 0x02:
			// AUT Cert
			JCSystem.beginTransaction();
			Util.arrayFillNonAtomic(cert3, (short) 0, (short) cert3.length, (byte) 0x00);
			cert3Len = (short) 0;
			JCSystem.commitTransaction();
			return;
		case (byte) 0xFF:
			// SM Cert
			JCSystem.beginTransaction();
			Util.arrayFillNonAtomic(cert4, (short) 0, (short) cert4.length, (byte) 0x00);
			cert4Len = (short) 0;
			JCSystem.commitTransaction();
			return;
		default:
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			return;
		}
	}

	private short doCertIOByIndicator(byte ind, boolean isWrite, byte[] ioBuff, short ioBuffOff, short storeOff, short len) {
		switch (ind) {
		case (byte) 0x00:
			// SIG Cert
			if (isWrite) {
				JCSystem.beginTransaction();
				Util.arrayCopy(ioBuff, ioBuffOff, cert1, storeOff, len);
				cert1Len += len;
				JCSystem.commitTransaction();
				return len;
			} else {
				return Util.arrayCopyNonAtomic(cert1, storeOff, ioBuff, ioBuffOff, len);				
			}
		case (byte) 0x01:
			// DEC Cert
			if (isWrite) {
				JCSystem.beginTransaction();
				Util.arrayCopy(ioBuff, ioBuffOff, cert2, storeOff, len);
				cert2Len += len;
				JCSystem.commitTransaction();
				return len;
			} else {
				return Util.arrayCopyNonAtomic(cert2, storeOff, ioBuff, ioBuffOff, len);
			}
		case (byte) 0x02:
			// AUT Cert
			if (isWrite) {
				JCSystem.beginTransaction();
				Util.arrayCopy(ioBuff, ioBuffOff, cert3, storeOff, len);
				cert3Len += len;
				JCSystem.commitTransaction();
				return len;
			} else {
				return Util.arrayCopyNonAtomic(cert3, storeOff, ioBuff, ioBuffOff, len);
			}
		case (byte) 0xFF:
			// SM Cert
			if (isWrite) {
				JCSystem.beginTransaction();
				Util.arrayCopy(ioBuff, ioBuffOff, cert4, storeOff, len);
				cert4Len += len;
				JCSystem.commitTransaction();
				return len;
			} else {
				return Util.arrayCopyNonAtomic(cert4, storeOff, ioBuff, ioBuffOff, len);
			}
		default:
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			return (short) 0;
		}
	}

}
