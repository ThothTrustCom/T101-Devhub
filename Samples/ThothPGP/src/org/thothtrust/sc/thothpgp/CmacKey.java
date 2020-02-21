/**
 * BSD-3-Clause
 * 
 * Copyright 2020 ThothTrust Pte Ltd.
 * 
 * Refer to LICENSE file for full license text.
 */
package org.thothtrust.sc.thothpgp;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public final class CmacKey {

    protected final AESKey key;
    protected final byte[] k1;
    protected final byte[] k2;

    protected CmacKey(final short aesKeyLength) {
        key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                                          (short)(aesKeyLength * 8),
                                          false);

        k1 = JCSystem.makeTransientByteArray(Constants.AES_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);

        k2 = JCSystem.makeTransientByteArray(Constants.AES_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
    }

    protected final boolean isInitialized() {
        return key.isInitialized();
    }

    protected final void clearKey() {
        key.clearKey();
        Util.arrayFillNonAtomic(k1, (short)0, (short)k1.length, (byte)0);
        Util.arrayFillNonAtomic(k2, (short)0, (short)k2.length, (byte)0);
    }

    protected final short getSize() {
        return key.getSize();
    }

    protected final void setKey(final byte[] buf, final short bufOff) {
        key.setKey(buf, bufOff);

        final Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

        cipher.init(key, Cipher.MODE_ENCRYPT);

        Util.arrayFillNonAtomic(k2, (short)0, Constants.AES_BLOCK_SIZE, (byte)0);
        cipher.doFinal(k2, (short)0, Constants.AES_BLOCK_SIZE,
                       k1, (short)0);

        final boolean mark = ((k1[0] & (byte)0x80) != (byte)0);
        Common.arrayLeftShift(k1, (short)0,
                              k1, (short)0,
                              Constants.AES_BLOCK_SIZE);
        if(mark) {
            k1[(short)(Constants.AES_BLOCK_SIZE - 1)] = (byte)(k1[(short)(Constants.AES_BLOCK_SIZE - 1)] ^ (byte)0x87);
        }

        Common.arrayLeftShift(k1, (short)0,
                              k2, (short)0,
                              Constants.AES_BLOCK_SIZE);
        if((k1[0] & (byte)0x80) != (byte)0) {
            k2[(short)(Constants.AES_BLOCK_SIZE - 1)] = (byte)(k2[(short)(Constants.AES_BLOCK_SIZE - 1)] ^ (byte)0x87);
        }
    }

}