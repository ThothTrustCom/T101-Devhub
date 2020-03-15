/**
 * BSD-3-Clause
 * 
 * Copyright 2020 ThothTrust Pte Ltd.
 * 
 * Refer to LICENSE file for full license text.
 */
package org.thothtrust.sc.thothpgp;

import javacard.framework.*;

public class Fingerprint {
	public byte[] data = null;

	public Fingerprint() {
		data = new byte[Constants.FINGERPRINT_SIZE];
	}

	public void reset(boolean isRegistering) {
		Common.beginTransaction(isRegistering);
		Util.arrayFillNonAtomic(data, (short) 0, Constants.FINGERPRINT_SIZE, (byte) 0);
		Common.commitTransaction(isRegistering);
	}

	public void set(byte[] buf, short off, short len) {
		if (len != Constants.FINGERPRINT_SIZE) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}
		Util.arrayCopy(buf, off, data, (short) 0, len);
	}

	public short write(byte[] buf, short off) {
		return Util.arrayCopyNonAtomic(data, (short) 0, buf, off, Constants.FINGERPRINT_SIZE);
	}
}