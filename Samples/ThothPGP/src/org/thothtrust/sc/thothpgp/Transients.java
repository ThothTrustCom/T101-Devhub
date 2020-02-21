/**
 * BSD-3-Clause
 * 
 * Copyright 2020 ThothTrust Pte Ltd.
 * 
 * Refer to LICENSE file for full license text.
 */
package org.thothtrust.sc.thothpgp;

import org.thothtrust.sc.thothpgp.Constants;
import javacard.framework.JCSystem;

public final class Transients {

    protected final byte[] buffer;

    private final short[] shorts;
    private static final byte SHORT_OFFSET_CURRENT_TAG = 0;
    private static final byte SHORT_OFFSET_OUTPUT_START = SHORT_OFFSET_CURRENT_TAG + 1;
    private static final byte SHORT_OFFSET_OUTPUT_LENGTH = SHORT_OFFSET_OUTPUT_START + 1;
    private static final byte SHORT_OFFSET_CHAINING_INPUT_LENGTH = SHORT_OFFSET_OUTPUT_LENGTH + 1;
    private static final byte SHORT_OFFSET_SECURE_MESSAGING_ENCRYPTION_COUNTER = SHORT_OFFSET_CHAINING_INPUT_LENGTH + 1;
    private static final byte SHORTS_SIZE = SHORT_OFFSET_SECURE_MESSAGING_ENCRYPTION_COUNTER + 1;

    private final byte[] bytes;
    private static final byte BYTE_OFFSET_CHAINING_INPUT_INS = 0;
    private static final byte BYTE_OFFSET_CHAINING_INPUT_P1 = BYTE_OFFSET_CHAINING_INPUT_INS + 1;
    private static final byte BYTE_OFFSET_CHAINING_INPUT_P2 = BYTE_OFFSET_CHAINING_INPUT_P1 + 1;
    private static final byte BYTE_OFFSET_CURRENT_TAG_OCCURRENCE = BYTE_OFFSET_CHAINING_INPUT_P2 + 1;
    private static final byte BYTES_SIZE = BYTE_OFFSET_CURRENT_TAG_OCCURRENCE + 1;

    private final boolean[] booleans;
    private static final byte BOOLEAN_OFFSET_CHAINING_OUTPUT = 0;
    private static final byte BOOLEAN_OFFSET_CHAINING_INPUT = BOOLEAN_OFFSET_CHAINING_OUTPUT + 1;
    private static final byte BOOLEAN_OFFSET_USER_PIN_MODE_81 = BOOLEAN_OFFSET_CHAINING_INPUT + 1;
    private static final byte BOOLEAN_OFFSET_USER_PIN_MODE_82 = BOOLEAN_OFFSET_USER_PIN_MODE_81 + 1;
    private static final byte BOOLEAN_OFFSET_SECURE_MESSAGING_OK = BOOLEAN_OFFSET_USER_PIN_MODE_82 + 1;
    private static final byte BOOLEANS_SIZE = BOOLEAN_OFFSET_SECURE_MESSAGING_OK + 1;


    protected Transients() {
        buffer = JCSystem.makeTransientByteArray(Constants.INTERNAL_BUFFER_MAX_LENGTH,
                                                 JCSystem.CLEAR_ON_DESELECT);
        shorts = JCSystem.makeTransientShortArray(SHORTS_SIZE,
                                                  JCSystem.CLEAR_ON_DESELECT);
        bytes = JCSystem.makeTransientByteArray(BYTES_SIZE,
                                                JCSystem.CLEAR_ON_DESELECT);
        booleans = JCSystem.makeTransientBooleanArray(BOOLEANS_SIZE,
                                                      JCSystem.CLEAR_ON_DESELECT);
    }

    protected final void clear() {
        for(byte i = 0; i < shorts.length; ++i) {
            shorts[i] = (short)0;
        }
        for(byte i = 0; i < bytes.length; ++i) {
            bytes[i] = (byte)0;
        }
        for(byte i = 0; i < booleans.length; ++i) {
            booleans[i] = false;
        }
    }

    protected final void setCurrentTag(final short tag) {
        shorts[SHORT_OFFSET_CURRENT_TAG] = tag;
    }

    protected final short currentTag() {
        return shorts[SHORT_OFFSET_CURRENT_TAG];
    }

    protected final void setChainingInputLength(final short len) {
        shorts[SHORT_OFFSET_CHAINING_INPUT_LENGTH] = len;
    }

    protected final short chainingInputLength() {
        return shorts[SHORT_OFFSET_CHAINING_INPUT_LENGTH];
    }

    protected final void setSecureMessagingEncryptionCounter(final short val) {
        shorts[SHORT_OFFSET_SECURE_MESSAGING_ENCRYPTION_COUNTER] = val;
    }

    protected final short secureMessagingEncryptionCounter() {
        return shorts[SHORT_OFFSET_SECURE_MESSAGING_ENCRYPTION_COUNTER];
    }

    protected final void setOutputStart(final short off) {
        shorts[SHORT_OFFSET_OUTPUT_START] = off;
    }

    protected final short outputStart() {
        return shorts[SHORT_OFFSET_OUTPUT_START];
    }

    protected final void setOutputLength(final short len) {
        shorts[SHORT_OFFSET_OUTPUT_LENGTH] = len;
    }

    protected final short outputLength() {
        return shorts[SHORT_OFFSET_OUTPUT_LENGTH];
    }

    protected final void setChainingInputIns(final byte ins) {
        bytes[BYTE_OFFSET_CHAINING_INPUT_INS] = ins;
    }

    protected final byte chainingInputIns() {
        return bytes[BYTE_OFFSET_CHAINING_INPUT_INS];
    }

    protected final void setChainingInputP1(final byte p1) {
        bytes[BYTE_OFFSET_CHAINING_INPUT_P1] = p1;
    }

    protected final byte chainingInputP1() {
        return bytes[BYTE_OFFSET_CHAINING_INPUT_P1];
    }

    protected final void setChainingInputP2(final byte p2) {
        bytes[BYTE_OFFSET_CHAINING_INPUT_P2] = p2;
    }

    protected final byte chainingInputP2() {
        return bytes[BYTE_OFFSET_CHAINING_INPUT_P2];
    }

    protected final void setCurrentTagOccurrence(final byte occ) {
        bytes[BYTE_OFFSET_CURRENT_TAG_OCCURRENCE] = occ;
    }

    protected final byte currentTagOccurrence() {
        return bytes[BYTE_OFFSET_CURRENT_TAG_OCCURRENCE];
    }

    protected final void setChainingOutput(final boolean chaining) {
        booleans[BOOLEAN_OFFSET_CHAINING_OUTPUT] = chaining;
    }

    protected final boolean chainingOutput() {
        return booleans[BOOLEAN_OFFSET_CHAINING_OUTPUT];
    }

    protected final void setChainingInput(final boolean chaining) {
        booleans[BOOLEAN_OFFSET_CHAINING_INPUT] = chaining;
    }

    protected final boolean chainingInput() {
        return booleans[BOOLEAN_OFFSET_CHAINING_INPUT];
    }

    protected final void setUserPinMode81(final boolean is81) {
        booleans[BOOLEAN_OFFSET_USER_PIN_MODE_81] = is81;
    }

    protected final boolean userPinMode81() {
        return booleans[BOOLEAN_OFFSET_USER_PIN_MODE_81];
    }

    protected final void setUserPinMode82(final boolean is82) {
        booleans[BOOLEAN_OFFSET_USER_PIN_MODE_82] = is82;
    }

    protected final boolean userPinMode82() {
        return booleans[BOOLEAN_OFFSET_USER_PIN_MODE_82];
    }

    protected final void setSecureMessagingOk(final boolean ok) {
        booleans[BOOLEAN_OFFSET_SECURE_MESSAGING_OK] = ok;
    }

    protected final boolean secureMessagingOk() {
        return booleans[BOOLEAN_OFFSET_SECURE_MESSAGING_OK];
    }
}