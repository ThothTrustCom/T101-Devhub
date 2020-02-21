/**
 * BSD-3-Clause
 * 
 * Copyright 2020 ThothTrust Pte Ltd.
 * 
 * Refer to LICENSE file for full license text.
 */
package org.thothtrust.sc.thothpgp;

import javacard.framework.*;

public final class Fingerprint {
    protected final byte[] data;

    protected Fingerprint() {
        data = new byte[Constants.FINGERPRINT_SIZE];
    }

    protected final void reset(final boolean isRegistering) {
        Common.beginTransaction(isRegistering);
        Util.arrayFillNonAtomic(data, (short)0, Constants.FINGERPRINT_SIZE, (byte)0);
        Common.commitTransaction(isRegistering);
    }

    protected final void set(final byte[] buf, final short off, final short len) {
        if(len != Constants.FINGERPRINT_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }
        Util.arrayCopy(buf, off, data, (short)0, len);
    }

    protected final short write(final byte[] buf, final short off) {
        return Util.arrayCopyNonAtomic(data, (short)0, buf, off, Constants.FINGERPRINT_SIZE);
    }
}