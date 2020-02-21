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

public final class Persistent {

    protected boolean isTerminated;

    protected final byte[] login;
    protected short login_length;

    protected final byte[] url;
    protected short url_length;

    protected final PGPKey[] pgp_keys;
    protected static final byte PGP_KEYS_OFFSET_SIG = 0;
    protected static final byte PGP_KEYS_OFFSET_DEC = PGP_KEYS_OFFSET_SIG + 1;
    protected static final byte PGP_KEYS_OFFSET_AUT = PGP_KEYS_OFFSET_DEC + 1;
    private static final byte PGP_KEYS_LENGTH = PGP_KEYS_OFFSET_AUT + 1;

    protected final Fingerprint[] fingerprints;
    protected static final byte FINGERPRINTS_OFFSET_CA = 0;
    protected static final byte FINGERPRINTS_OFFSET_CB = FINGERPRINTS_OFFSET_CA + 1;
    protected static final byte FINGERPRINTS_OFFSET_CC = FINGERPRINTS_OFFSET_CB + 1;
    private static final byte FINGERPRINTS_LENGTH = FINGERPRINTS_OFFSET_CC + 1;

    protected final byte[] name;
    protected byte name_length;

    protected final byte[] lang;
    protected byte lang_length;

    protected byte sex;


    protected final byte[] digital_signature_counter;


    protected final byte[] do_0101;
    protected short do_0101_length;

    protected final byte[] do_0102;
    protected short do_0102_length;

    protected final byte[] do_0103;
    protected short do_0103_length;

    protected final byte[] do_0104;
    protected short do_0104_length;


    protected AESKey aes_key;


    protected final byte[] key_derivation_function;
    protected short key_derivation_function_length;

    protected final OwnerPIN user_pin; /* PW1 */
    protected byte user_pin_length;
    protected boolean user_pin_force_verify_signature;

    protected final OwnerPIN user_puk; /* resetting code */
    protected byte user_puk_length;

    protected final OwnerPIN admin_pin; /* PW3 */
    protected byte admin_pin_length;



    protected Persistent() {
        login = new byte[Constants.specialDoMaxLength()];
        login_length = 0;

        url = new byte[Constants.specialDoMaxLength()];
        url_length = 0;

        fingerprints = new Fingerprint[FINGERPRINTS_LENGTH];
        for(byte i = 0; i < fingerprints.length; ++i) {
            fingerprints[i] = new Fingerprint();
        }

        name = new byte[Constants.NAME_MAX_LENGTH];
        name_length = 0;

        lang = new byte[Constants.LANG_MAX_LENGTH];
        lang_length = 0;

        digital_signature_counter = new byte[3];

        do_0101 = new byte[Constants.specialDoMaxLength()];
        do_0101_length = 0;

        do_0102 = new byte[Constants.specialDoMaxLength()];
        do_0101_length = 0;

        do_0103 = new byte[Constants.specialDoMaxLength()];
        do_0103_length = 0;

        do_0104 = new byte[Constants.specialDoMaxLength()];
        do_0104_length = 0;

        aes_key = null;

        pgp_keys = new PGPKey[PGP_KEYS_LENGTH];
        for(byte i = 0; i < pgp_keys.length; ++i) {
            pgp_keys[i] = new PGPKey(false);
        }

        key_derivation_function = new byte[Constants.specialDoMaxLength()];
        key_derivation_function_length = 0;

        user_pin = new OwnerPIN(Constants.USER_PIN_RETRY_COUNT, Constants.USER_PIN_MAX_SIZE);
        user_puk = new OwnerPIN(Constants.USER_PUK_RETRY_COUNT, Constants.USER_PUK_MAX_SIZE);
        admin_pin = new OwnerPIN(Constants.ADMIN_PIN_RETRY_COUNT, Constants.ADMIN_PIN_MAX_SIZE);

        reset(true);
    }

    protected void reset(final boolean isRegistering) {
        for(byte i = 0; i < pgp_keys.length; ++i) {
            pgp_keys[i].reset(isRegistering);
        }

        if(login_length > 0) {
            Common.beginTransaction(isRegistering);
            Util.arrayFillNonAtomic(login, (short)0, login_length, (byte)0);
            login_length = (short)0;
            Common.commitTransaction(isRegistering);
        }

        if(url_length > 0) {
            Common.beginTransaction(isRegistering);
            Util.arrayFillNonAtomic(url, (short)0, url_length, (byte)0);
            url_length = (short)0;
            Common.commitTransaction(isRegistering);
        }

        for(byte i = 0; i < fingerprints.length; ++i) {
            fingerprints[i].reset(isRegistering);
        }

        if(name_length > 0) {
            Common.beginTransaction(isRegistering);
            Util.arrayFillNonAtomic(name, (short)0, name_length, (byte)0);
            name_length = (byte)0;
            Common.commitTransaction(isRegistering);
        }

        Common.beginTransaction(isRegistering);
        if(lang_length > 0) {
            Util.arrayFillNonAtomic(lang, (short)0, lang_length, (byte)0);
        }
        Util.arrayCopyNonAtomic(Constants.LANG_DEFAULT, (short)0,
                                lang, (short)0,
                                (short)Constants.LANG_DEFAULT.length);
        lang_length = (byte)Constants.LANG_DEFAULT.length;
        Common.commitTransaction(isRegistering);

        sex = Constants.SEX_NOT_ANNOUNCED;

        Util.arrayFillNonAtomic(digital_signature_counter, (short)0,
                                (short)digital_signature_counter.length, (byte)0);

        Common.beginTransaction(isRegistering);
        if(do_0101_length > 0) {
            Util.arrayFillNonAtomic(do_0101, (short)0,
                                    (short)do_0101.length, (byte)0);
            do_0101_length = 0;
        }
        Common.commitTransaction(isRegistering);

        Common.beginTransaction(isRegistering);
        if(do_0102_length > 0) {
            Util.arrayFillNonAtomic(do_0102, (short)0,
                                    (short)do_0102.length, (byte)0);
            do_0102_length = 0;
        }
        Common.commitTransaction(isRegistering);

        Common.beginTransaction(isRegistering);
        if(do_0103_length > 0) {
            Util.arrayFillNonAtomic(do_0103, (short)0,
                                    (short)do_0103.length, (byte)0);
            do_0103_length = 0;
        }
        Common.commitTransaction(isRegistering);

        Common.beginTransaction(isRegistering);
        if(do_0104_length > 0) {
            Util.arrayFillNonAtomic(do_0104, (short)0,
                                    (short)do_0104.length, (byte)0);
            do_0104_length = 0;
        }
        Common.commitTransaction(isRegistering);

        Common.beginTransaction(isRegistering);
        if(aes_key != null) {
            aes_key.clearKey();
            aes_key = null;
        }
        Common.commitTransaction(isRegistering);

        user_pin_force_verify_signature = Constants.USER_PIN_DEFAULT_FORCE_VERIFY_SIGNATURE;

        Common.beginTransaction(isRegistering);
        if(key_derivation_function_length > 0) {
            Util.arrayFillNonAtomic(key_derivation_function, (short)0, key_derivation_function_length, (byte)0);
        }
        Util.arrayCopyNonAtomic(Constants.KEY_DERIVATION_FUNCTION_DEFAULT, (short)0,
                                key_derivation_function, (short)0,
                                (short)Constants.KEY_DERIVATION_FUNCTION_DEFAULT.length);
        key_derivation_function_length = (short)Constants.KEY_DERIVATION_FUNCTION_DEFAULT.length;
        Common.commitTransaction(isRegistering);

        Common.beginTransaction(isRegistering);
        user_pin_length = (byte)Constants.USER_PIN_DEFAULT.length;
        user_pin.update(Constants.USER_PIN_DEFAULT, (short)0, user_pin_length);
        user_pin.resetAndUnblock();
        Common.commitTransaction(isRegistering);

        Common.beginTransaction(isRegistering);
        user_puk_length = (short)0;
        /* Ensures any previously defined PUK code is blocked at factory reset */
        byte[] emptyPin = new byte[1];
        while(user_puk.getTriesRemaining() > 0) {
            if(user_puk.check(emptyPin, (short)0, (byte)emptyPin.length)) {
                ISOException.throwIt((short)0x9999);
            }
        }
        Common.commitTransaction(isRegistering);

        Common.beginTransaction(isRegistering);
        admin_pin_length = (byte)Constants.ADMIN_PIN_DEFAULT.length;
        admin_pin.update(Constants.ADMIN_PIN_DEFAULT, (short)0, admin_pin_length);
        admin_pin.resetAndUnblock();
        Common.commitTransaction(isRegistering);

        isTerminated = false;
    }

    protected final boolean keyDerivationIsActive() {
        return ((3 <= key_derivation_function_length) &&
                (key_derivation_function[0] == (byte)0x81) &&
                (key_derivation_function[2] != (byte)0));
    }

    protected final byte keyDerivationSize() {
        if(keyDerivationIsActive() &&
           (6 <= key_derivation_function_length)) {
            switch(key_derivation_function[5]) {
            case (byte)0x08:
                return (byte)32;
            case (byte)0x0A:
                return (byte)64;
            default:
                return (byte)0;
            }
        }
        return (byte)0;
    }
}