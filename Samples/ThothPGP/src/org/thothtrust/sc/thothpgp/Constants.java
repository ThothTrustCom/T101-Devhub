/**
 * BSD-3-Clause
 * 
 * Copyright 2020 ThothTrust Pte Ltd.
 * 
 * Refer to LICENSE file for full license text.
 */
package org.thothtrust.sc.thothpgp;

import javacard.framework.Util;

public class Constants {

	static final short INTERNAL_BUFFER_MAX_LENGTH = (short) 0x500;

//	static final short APDU_MAX_LENGTH = (short) 256;

	static final byte[] KEY_DERIVATION_FUNCTION_DEFAULT = { (byte) 0x81, (byte) 0x01, (byte) 0x00 };

	static final byte USER_PIN_RETRY_COUNT = 3;
	static final byte USER_PIN_MIN_SIZE = 0x06;
	static final byte USER_PIN_MAX_SIZE = 0x7f; /* max is 0x7f because PIN format 2 */
	static final byte[] USER_PIN_DEFAULT = { (byte) 0x32, (byte) 0x32 };
//	static final byte[] USER_PIN_DEFAULT = { (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35,
//			(byte) 0x36 };

	static final boolean USER_PIN_DEFAULT_FORCE_VERIFY_SIGNATURE = true;

	static final byte USER_PUK_RETRY_COUNT = 3;
	static final byte USER_PUK_MIN_SIZE = 0x08;
	static final byte USER_PUK_MAX_SIZE = 0x7f; /* max is 0x7f because PIN format 2 */

	static final byte ADMIN_PIN_RETRY_COUNT = 3;
	static final byte ADMIN_PIN_MIN_SIZE = 0x08;
	static final byte ADMIN_PIN_MAX_SIZE = 0x7f; /* max is 0x7f because PIN format 2 */
	static final byte[] ADMIN_PIN_DEFAULT = { (byte) 0x31, (byte) 0x31 };
//	static final byte[] ADMIN_PIN_DEFAULT = { (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35,
//			(byte) 0x36, (byte) 0x37, (byte) 0x38 };

	static final byte FINGERPRINT_SIZE = 20;
	static final byte GENERATION_DATE_SIZE = 4;

	static final byte NAME_MAX_LENGTH = 39;
	static final byte LANG_MIN_LENGTH = 2;
	static final byte LANG_MAX_LENGTH = 8;
	static final byte[] LANG_DEFAULT = { (byte) 0x65, (byte) 0x6e };

	static final byte SEX_MALE = (byte) 0x31;
	static final byte SEX_FEMALE = (byte) 0x32;
	static final byte SEX_NOT_ANNOUNCED = (byte) 0x39;

	static final short TAG_AID = (short) 0x004f;
	static final short TAG_LOGIN = (short) 0x005e;
	static final short TAG_URL = (short) 0x5f50;
	static final short TAG_HISTORICAL_BYTES_CARD_SERVICE_CARD_CAPABILITIES = (short) 0x5f52;
	static final short TAG_CARDHOLDER_RELATED_DATA = (short) 0x0065;
	static final short TAG_APPLICATION_RELATED_DATA = (short) 0x006e;
	static final short TAG_SECURITY_SUPPORT_TEMPLATE = (short) 0x007a;
	static final short TAG_CARDHOLDER_CERTIFICATE = (short) 0x7f21;
	static final short TAG_NAME = (short) 0x005b;
	static final short TAG_LANG = (short) 0x5f2d;
	static final short TAG_SEX = (short) 0x5f35;
	static final short TAG_ALGORITHM_ATTRIBUTES_SIG = (short) 0x00c1;
	static final short TAG_ALGORITHM_ATTRIBUTES_DEC = (short) 0x00c2;
	static final short TAG_ALGORITHM_ATTRIBUTES_AUT = (short) 0x00c3;
	static final short TAG_ALGORITHM_ATTRIBUTES_SM = (short) 0x00d4;
	static final short TAG_PW_STATUS = (short) 0x00c4;
	static final short TAG_KEY_FINGERPRINTS = (short) 0x00c5;
	static final short TAG_CA_FINGERPRINTS = (short) 0x00c6;
	static final short TAG_FINGERPRINT_SIG = (short) 0x00c7;
	static final short TAG_FINGERPRINT_DEC = (short) 0x00c8;
	static final short TAG_FINGERPRINT_AUT = (short) 0x00c9;
	static final short TAG_FINGERPRINT_CA = (short) 0x00ca;
	static final short TAG_FINGERPRINT_CB = (short) 0x00cb;
	static final short TAG_FINGERPRINT_CC = (short) 0x00cc;
	static final short TAG_KEY_GENERATION_DATES = (short) 0x00cd;
	static final short TAG_GENERATION_DATE_SIG = (short) 0x00ce;
	static final short TAG_GENERATION_DATE_DEC = (short) 0x00cf;
	static final short TAG_GENERATION_DATE_AUT = (short) 0x00d0;
	static final short TAG_KEY_INFORMATION = (short) 0x00de;
	static final short TAG_RESETTING_CODE = (short) 0x00d3;
	static final short TAG_EXTENDED_LENGTH_INFORMATION = (short) 0x7f66;
	static final short TAG_PRIVATE_DO_0101 = (short) 0x0101;
	static final short TAG_PRIVATE_DO_0102 = (short) 0x0102;
	static final short TAG_PRIVATE_DO_0103 = (short) 0x0103;
	static final short TAG_PRIVATE_DO_0104 = (short) 0x0104;
	static final short TAG_AES_KEY = (short) 0x00d5;
	static final short TAG_KEY_DERIVATION_FUNCTION = (short) 0x00f9;
	static final short TAG_ALGORITHM_INFORMATION = (short) 0x00fa;
	static final short TAG_SECURE_MESSAGING_CERTIFICATE = (short) 0x00fb;

	static final byte CRT_TAG_AUTHENTICATION_KEY = (byte) 0xa4;
	static final byte CRT_TAG_SECURE_MESSAGING_KEY = (byte) 0xa6;
	static final byte CRT_TAG_SIGNATURE_KEY = (byte) 0xb6;
	static final byte CRT_TAG_DECRYPTION_KEY = (byte) 0xb8;

	static final byte CLA_MASK_CHAINING = (byte) 0x10;
	static final byte CLA_MASK_SECURE_MESSAGING = (byte) 0x04;

	static final byte INS_SELECT_DATA = (byte) 0xA5;
	static final byte INS_GET_DATA = (byte) 0xCA;
	static final byte INS_GET_NEXT_DATA = (byte) 0xCC;
	static final byte INS_VERIFY = (byte) 0x20;
	static final byte INS_CHANGE_REFERENCE_DATA = (byte) 0x24;
	static final byte INS_RESET_RETRY_COUNTER = (byte) 0x2C;
	static final byte INS_PUT_DATA_DA = (byte) 0xDA;
	static final byte INS_PUT_DATA_DB = (byte) 0xDB;
	static final byte INS_GENERATE_ASYMMETRIC_KEY_PAIR = (byte) 0x47;
	static final byte INS_PERFORM_SECURITY_OPERATION = (byte) 0x2A;
	static final byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;
	static final byte INS_GET_RESPONSE = (byte) 0xC0;
	static final byte INS_GET_CHALLENGE = (byte) 0x84;
	static final byte INS_TERMINATE_DF = (byte) 0xE6;
	static final byte INS_ACTIVATE_FILE = (byte) 0x44;

	static final short SW_TERMINATED = (short) 0x6285;
	static final short SW_MEMORY_FAILURE = (short) 0x6581;
	static final short SW_CHAINING_ERROR = (short) 0x6883;
	static final short SW_REFERENCE_DATA_NOT_FOUND = (short) 0x6A88;

	static final byte[] HISTORICAL_BYTES = { (byte) 0x00, /* category indicator byte */

			(byte) 0xC1, /* card service data */
			(byte) 0xC5, /* ... */

			(byte) 0x73, /* card capabilities */
			(byte) 0xC0, /* 1st byte: "methods supported" see ISO 7816-4 */
			(byte) 0x01, /* 2nd byte: "data coding byte" idem */
			(byte) 0x80, /*
							 * 3rd byte: command chaining (not extended length by default as all readers do
							 * not support them...)
							 */

			(byte) 0x05, /* status indicator byte : operational state */
			(byte) 0x90, /* SW1 */
			(byte) 0x00 /* SW2 */
	};

	static final byte[] EXTENDED_CAPABILITIES = { (byte) (0x80 | /* support secure messaging */
			0x40 | /* support get challenge */
			0x00 | /*
					 * support key import - CURRENTLY DISABLED DUE TO NO RSA CRT PRIVKEY SUPPORT. IF
					 * SUPPORT FOR RSA CRT PRIV ENABLED, USE 0x20
					 */
			0x10 | /* support pw status changes */
			0x08 | /* support private DOs (0101-0104) */
			0x00 | /* support algorithm attributes changes */
			0x02 | /* support PSO:DEC/ENC AES */
			0x00), /* support KDF-DO - CURRENTLY DISABLED AS PIN USAGE FROM FRONT PANEL ONLY */
			(byte) 0x00, /* SM 0x01 = 128 bits, 0x02 = 256 bits, 0x03 = SCP11b */
			(byte) 0x00, (byte) 0x20, /* max length get challenge */
			(byte) 0x04, (byte) 0x80, /* max length of carholder certificate */
			(byte) 0x00, (byte) 0xff, /* max length of special DOs (private, login, url, KDF-DO) */
			(byte) 0x00, /* PIN format 2 is not supported */
			(byte) 0x00 /* MSE not supported */
	};

	static short challengeMaxLength() {
		return Util.getShort(EXTENDED_CAPABILITIES, (short) 2);
	}

	static short cardholderCertificateMaxLength() {
		return Util.getShort(EXTENDED_CAPABILITIES, (short) 4);
	}

	static short specialDoMaxLength() {
		return Util.getShort(EXTENDED_CAPABILITIES, (short) 6);
	}

	static final byte[] DSI_SHA256_HEADER = { (byte) 0x30, (byte) 0x31, (byte) 0x30, (byte) 0x0D, (byte) 0x06,
			(byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03, (byte) 0x04,
			(byte) 0x02, (byte) 0x01, (byte) 0x05, (byte) 0x00, (byte) 0x04, (byte) 0x20 };

	static final byte[] DSI_SHA384_HEADER = { (byte) 0x30, (byte) 0x41, (byte) 0x30, (byte) 0x0D, (byte) 0x06,
			(byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03, (byte) 0x04,
			(byte) 0x02, (byte) 0x02, (byte) 0x05, (byte) 0x00, (byte) 0x04, (byte) 0x30 };

	static final byte[] DSI_SHA512_HEADER = { (byte) 0x30, (byte) 0x51, (byte) 0x30, (byte) 0x0D, (byte) 0x06,
			(byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03, (byte) 0x04,
			(byte) 0x02, (byte) 0x03, (byte) 0x05, (byte) 0x00, (byte) 0x04, (byte) 0x40 };

	static final byte ALGORITHM_ATTRIBUTES_MIN_LENGTH = 6;
	static final byte ALGORITHM_ATTRIBUTES_MAX_LENGTH = 13;

	static final byte[] ALGORITHM_ATTRIBUTES_DEFAULT = { (byte) 0x01, /* RSA */
			(byte) 0x08, (byte) 0x00, /* 2048 bits modulus */
			(byte) 0x00, (byte) 0x11, /* 65537 = 17 bits public exponent */
			(byte) 0x03 /* crt form with modulus */
	};

	static final byte[] ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING = { (byte) 0x12, /* ECDH */
			(byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0xCE, (byte) 0x3D, (byte) 0x03, (byte) 0x01, (byte) 0x07, /*
																													 * ansix9p256r1
																													 */
			(byte) 0xFF /* with public key */
	};

	static final byte[] RSA_EXPONENT = { (byte) 0x01, (byte) 0x00, (byte) 0x01 };

	static final short AES_BLOCK_SIZE = (short) 16;

}