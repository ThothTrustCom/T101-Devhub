package org.thothtrust.sc.thothpgp;

import KM101.T101OpenAPI;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyAgreement;
import javacard.security.MessageDigest;

public class APIShim {
	private byte[] aocPin;
	private byte[] pukUserPin;
	private byte[] nonceBuffer = JCSystem.makeTransientByteArray((short) 8, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
	private byte[] appName = { (byte) 0x4f, (byte) 0x70, (byte) 0x65, (byte) 0x6e, (byte) 0x50, (byte) 0x47,
			(byte) 0x50 };
	public static final byte[] adminName = { (byte) 0x61, (byte) 0x64, (byte) 0x6d };
	public static final byte[] pukName = { (byte) 0x70, (byte) 0x75, (byte) 0x6b };
	public static final byte[] userName = { (byte) 0x75, (byte) 0x73, (byte) 0x72 };
	public static final byte[] keyHandleSign = { (byte) 0x73, (byte) 0x69, (byte) 0x67, (byte) 0x4b };
	public static final byte[] keyHandleCipher = { (byte) 0x63, (byte) 0x69, (byte) 0x70, (byte) 0x4b };
	public static final byte[] keyHandleAuth = { (byte) 0x61, (byte) 0x75, (byte) 0x74, (byte) 0x4b };
	public static final byte[] keyHandleSM = { (byte) 0x73, (byte) 0x6d, (byte) 0x65, (byte) 0x4b };
	public static final byte[] defaultExpiryTime = new byte[4];
	private short aocPinMaxRetry = 5;
	private byte[] tempBuf = null;
	public static final byte[] TXT_CHANGE_PIN_TITLE = { (byte) 0x55, (byte) 0x70, (byte) 0x64, (byte) 0x74, (byte) 0x65,
			(byte) 0x20, (byte) 0x50, (byte) 0x49, (byte) 0x4e };
	public static final byte[] TXT_RESET_PIN_TITLE = { (byte) 0x52, (byte) 0x65, (byte) 0x73, (byte) 0x65, (byte) 0x74,
			(byte) 0x20, (byte) 0x50, (byte) 0x49, (byte) 0x4e };
	public static final byte[] TXT_NEW_PIN = { (byte) 0x4e, (byte) 0x65, (byte) 0x77, (byte) 0x20, (byte) 0x50,
			(byte) 0x49, (byte) 0x4e };
	public static final byte[] TXT_NEW_PUK_TITLE = { (byte) 0x4e, (byte) 0x65, (byte) 0x77, (byte) 0x20, (byte) 0x50,
			(byte) 0x55, (byte) 0x4b };
	public static final byte[] TXT_RESET_CARD_TITLE = { (byte) 0x57, (byte) 0x49, (byte) 0x50, (byte) 0x45, (byte) 0x20,
			(byte) 0x43, (byte) 0x41, (byte) 0x52, (byte) 0x44 };
	public static final byte[] TXT_RESET_CARD = { (byte) 0x50, (byte) 0x72, (byte) 0x65, (byte) 0x73, (byte) 0x73,
			(byte) 0x20, (byte) 0x4f, (byte) 0x4b, (byte) 0x20, (byte) 0x74, (byte) 0x6f, (byte) 0x20, (byte) 0x77,
			(byte) 0x69, (byte) 0x70, (byte) 0x65, (byte) 0x20, (byte) 0x63, (byte) 0x61, (byte) 0x72, (byte) 0x64,
			(byte) 0x20, (byte) 0x6f, (byte) 0x72, (byte) 0x20, (byte) 0x43, (byte) 0x20, (byte) 0x74, (byte) 0x6f,
			(byte) 0x20, (byte) 0x61, (byte) 0x62, (byte) 0x6f, (byte) 0x72, (byte) 0x74, (byte) 0x2e };
	public static final byte[] TXT_SUCCESS = new byte[] { (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x4f,
			(byte) 0x70, (byte) 0x65, (byte) 0x72, (byte) 0x61, (byte) 0x74, (byte) 0x69, (byte) 0x6f, (byte) 0x6e,
			(byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20,
			(byte) 0x53, (byte) 0x75, (byte) 0x63, (byte) 0x63, (byte) 0x65, (byte) 0x73, (byte) 0x73, (byte) 0x20,
			(byte) 0x20, (byte) 0x20, (byte) 0x20 };
	public static final byte[] TXT_FAILED = new byte[] { (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x4f,
			(byte) 0x70, (byte) 0x65, (byte) 0x72, (byte) 0x61, (byte) 0x74, (byte) 0x69, (byte) 0x6f, (byte) 0x6e,
			(byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20,
			(byte) 0x46, (byte) 0x61, (byte) 0x69, (byte) 0x6c, (byte) 0x65, (byte) 0x64, (byte) 0x20, (byte) 0x20,
			(byte) 0x20, (byte) 0x20, (byte) 0x20 };
	public static final byte[] TXT_CRYPT_OPS_TITLE = new byte[] { (byte) 0x43, (byte) 0x72, (byte) 0x79, (byte) 0x70,
			(byte) 0x74, (byte) 0x20, (byte) 0x4f, (byte) 0x70, (byte) 0x73 };
	public static final byte[] TXT_SIG_OPS_TITLE = new byte[] { (byte) 0x53, (byte) 0x69, (byte) 0x67, (byte) 0x6e,
			(byte) 0x20, (byte) 0x4f, (byte) 0x70, (byte) 0x73 };
	public static final byte[] TXT_CRYPT_OPS = { (byte) 0x50, (byte) 0x72, (byte) 0x65, (byte) 0x73, (byte) 0x73,
			(byte) 0x20, (byte) 0x4f, (byte) 0x4b, (byte) 0x20, (byte) 0x74, (byte) 0x6f, (byte) 0x20, (byte) 0x64,
			(byte) 0x65, (byte) 0x63, (byte) 0x72, (byte) 0x79, (byte) 0x70, (byte) 0x74, (byte) 0x20, (byte) 0x64,
			(byte) 0x61, (byte) 0x74, (byte) 0x61, (byte) 0x20, (byte) 0x6f, (byte) 0x72, (byte) 0x20, (byte) 0x43,
			(byte) 0x20, (byte) 0x74, (byte) 0x6f, (byte) 0x20, (byte) 0x61, (byte) 0x62, (byte) 0x6f, (byte) 0x72,
			(byte) 0x74, (byte) 0x2e };
	public static final byte[] TXT_SIG_OPS = { (byte) 0x50, (byte) 0x72, (byte) 0x65, (byte) 0x73, (byte) 0x73,
			(byte) 0x20, (byte) 0x4f, (byte) 0x4b, (byte) 0x20, (byte) 0x74, (byte) 0x6f, (byte) 0x20, (byte) 0x73,
			(byte) 0x69, (byte) 0x67, (byte) 0x6e, (byte) 0x20, (byte) 0x64, (byte) 0x61, (byte) 0x74, (byte) 0x61,
			(byte) 0x20, (byte) 0x6f, (byte) 0x72, (byte) 0x20, (byte) 0x43, (byte) 0x20, (byte) 0x74, (byte) 0x6f,
			(byte) 0x20, (byte) 0x61, (byte) 0x62, (byte) 0x6f, (byte) 0x72, (byte) 0x74, (byte) 0x2e };
	public static final byte[] TXT_LOGIN_ADM_TITLE = { (byte) 0x4c, (byte) 0x6f, (byte) 0x67, (byte) 0x69, (byte) 0x6e,
			(byte) 0x20, (byte) 0x41, (byte) 0x64, (byte) 0x6d };
	public static final byte[] TXT_LOGIN_USR_TITLE = { (byte) 0x4c, (byte) 0x6f, (byte) 0x67, (byte) 0x69, (byte) 0x6e,
			(byte) 0x20, (byte) 0x55, (byte) 0x73, (byte) 0x72 };
	public static final byte[] TXT_LOGIN = { (byte) 0x50, (byte) 0x72, (byte) 0x65, (byte) 0x73, (byte) 0x73,
			(byte) 0x20, (byte) 0x4f, (byte) 0x4b, (byte) 0x20, (byte) 0x74, (byte) 0x6f, (byte) 0x20, (byte) 0x6c,
			(byte) 0x6f, (byte) 0x67, (byte) 0x69, (byte) 0x6e, (byte) 0x20, (byte) 0x6f, (byte) 0x72, (byte) 0x20,
			(byte) 0x43, (byte) 0x20, (byte) 0x74, (byte) 0x6f, (byte) 0x20, (byte) 0x61, (byte) 0x62, (byte) 0x6f,
			(byte) 0x72, (byte) 0x74, (byte) 0x2e };

	public APIShim() {
		aocPin = new byte[8];
		generateRandomAOCPin(aocPin, (short) 0, (short) aocPin.length);
	}

	private void generateRandomAOCPin(byte[] pin, short off, short len) {
		ThothPGPApplet.random_data.generateData(nonceBuffer, (short) 0, (short) len);
		for (short i = (short) 0; i < len; i++) {
//			 Use the rightmost 4 nibbles of bytes from random byte and mod 10 to get a
//			 numerical digit and then convert back to its byte form
			pin[(short) (i + off)] = (byte) (((short) ((byte) (nonceBuffer[i] & 0x0F) % (short) 10) & 0xFF) | 0x30);
		}
	}

	public byte[] getKeyHandle(byte pgpKeysOffset) {
		switch (pgpKeysOffset) {
		case Persistent.PGP_KEYS_OFFSET_SIG:
			return keyHandleSign;
		case Persistent.PGP_KEYS_OFFSET_DEC:
			return keyHandleCipher;
		case Persistent.PGP_KEYS_OFFSET_AUT:
			return keyHandleAuth;
		default:
			return keyHandleSM;
		}
	}

	private short rsaOps(byte mode, byte ind, byte[] input, short inOff, short inLen, byte[] output, short outOff,
			byte[] apduBuffer) {

		short uploadSize = 0;
		short downloadSize = 0;

		// Clear compute buffer
		clearUploadBuffer(apduBuffer);

		// Load input into compute buffer
		for (short i = 0; i < (short) (inLen - 1);) {
			if ((short) (inLen - i - 1) > (short) 200) {
				uploadSize = (short) 200;
			} else {
				uploadSize = (short) (inLen - i - 1);
			}
			if (i == 0) {
				if (!uploadToBuffer(false, (short) (inLen - 1), input, (short) (i + inOff), uploadSize, apduBuffer)) {
					return (short) -1;
				}
			} else {
				if (!uploadToBuffer(true, (short) 0, input, (short) (i + inOff), uploadSize, apduBuffer)) {
					return (short) -1;
				}
			}
			i += uploadSize;
		}

		// Load RSA decryption key
		if (executeObject(T101OpenAPI.EXEC_CRYPT_CONTENT_EXTRACT, T101OpenAPI.CRYPT_LOAD, mode, false, ind, appName,
				(short) 0, (short) 1, apduBuffer) == (short) -1) {
			return (short) -1;
		}

		// Execute RSA decrypt on buffer data
		downloadSize = executeObject(T101OpenAPI.EXEC_CRYPT_CONTENT_EXTRACT, T101OpenAPI.CRYPT_FINAL, mode, true, ind,
				input, (short) (inOff + inLen - 1), (short) 1, apduBuffer);
		if (downloadSize == (short) -1) {
			return (short) -1;
		}

		// Copy to output
		Util.arrayCopyNonAtomic(apduBuffer, (short) 0, output, outOff, downloadSize);

		// Clear temp buffer
		clearUploadBuffer(apduBuffer);

		return downloadSize;
//		return inLen;
	}

	/**
	 * Decrypts RSA enciphered data. Output buffer cannot be an APDU buffer.
	 * 
	 * @param keyHandle
	 * @param handleOff
	 * @param handleLen
	 * @param input
	 * @param inOff
	 * @param inLen
	 * @param output
	 * @param outOff
	 * @param apduBuffer
	 * @return
	 */
	public short decryptRSA(byte ind, byte[] input, short inOff, short inLen, byte[] output, short outOff,
			byte[] apduBuffer) {
		if (confirmationUI(TXT_CRYPT_OPS_TITLE, (short) 0, (short) TXT_CRYPT_OPS_TITLE.length, TXT_CRYPT_OPS, (short) 0,
				(short) TXT_CRYPT_OPS.length, apduBuffer)) {
			return rsaOps((byte) 0x01, ind, input, inOff, inLen, output, outOff, apduBuffer);
		}

		return 0;
	}

	/**
	 * Signing is done via raw RSA decrypt mode over raw (presumably formatted)
	 * data.
	 * 
	 * @param keyHandle
	 * @param handleOff
	 * @param handleLen
	 * @param message
	 * @param msgOff
	 * @param msgLen
	 * @param signature
	 * @param sigOff
	 * @param sigLen
	 * @param output
	 * @param outOff
	 * @param apduBuffer
	 * @return
	 */
	public short signRSA(byte ind, byte[] message, short msgOff, short msgLen, byte[] output, short outOff,
			byte[] apduBuffer) {
		if (confirmationUI(TXT_SIG_OPS_TITLE, (short) 0, (short) TXT_SIG_OPS_TITLE.length, TXT_SIG_OPS, (short) 0,
				(short) TXT_SIG_OPS.length, apduBuffer)) {
			return rsaOps((byte) 0x00, ind, message, msgOff, msgLen, output, outOff, apduBuffer);
		}

		return 0;
	}

	/**
	 * Performs ECDH using selected ECC key. APDU buffer with offset of 0 will be
	 * used to store output.
	 * 
	 * @param keyHandle
	 * @param handleOff
	 * @param handleLen
	 * @param publicKey
	 * @param keyOff
	 * @param keyLen
	 * @param apduBuffer
	 * @return
	 */
	public short ecdh(byte ind, byte[] publicKey, short keyOff, short keyLen, byte[] apduBuffer) {
		if (confirmationUI(TXT_CRYPT_OPS_TITLE, (short) 0, (short) TXT_CRYPT_OPS_TITLE.length, TXT_CRYPT_OPS, (short) 0,
				(short) TXT_CRYPT_OPS.length, apduBuffer)) {

			// Load ECC Key
			if (executeObject(T101OpenAPI.EXEC_CRYPT_CONTENT_PROTECT, T101OpenAPI.CRYPT_LOAD,
					KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false, ind, null, (short) 0, (short) 0,
					apduBuffer) == (short) -1) {
				return (short) -1;
			}

			// Execute ECDH
			return executeObject(T101OpenAPI.EXEC_CRYPT_CONTENT_PROTECT, T101OpenAPI.CRYPT_FINAL,
					KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false, ind, publicKey, keyOff, keyLen, apduBuffer);
		}

		return (short) 0;
	}

	/**
	 * Perform ECDSA over pre-computed hash. APDU buffer with offset of 0 will be
	 * used to store output.
	 * 
	 * @param keyHandle
	 * @param handleOff
	 * @param handleLen
	 * @param message
	 * @param msgOff
	 * @param msgLen
	 * @param apduBuffer
	 * @return
	 */
	public short signPreComputeHashECDSA(byte ind, byte[] message, short msgOff, short msgLen, byte[] apduBuffer) {
		if (confirmationUI(TXT_SIG_OPS_TITLE, (short) 0, (short) TXT_SIG_OPS_TITLE.length, TXT_SIG_OPS, (short) 0,
				(short) TXT_SIG_OPS.length, apduBuffer)) {
			// Load ECC Key
			if (executeObject(T101OpenAPI.EXEC_CRYPT_INTEGRITY_CREATION, T101OpenAPI.CRYPT_LOAD, (byte) 0x00, false,
					ind, null, (short) 0, (short) 0, apduBuffer) == (short) -1) {
				return (short) -1;
			}

			// Execute ECDSA
			return executeObject(T101OpenAPI.EXEC_CRYPT_INTEGRITY_CREATION, T101OpenAPI.CRYPT_FINAL, (byte) 0x00, false,
					ind, message, msgOff, msgLen, apduBuffer);
		}

		return (short) 0;
	}

	public short getPublicKey(byte[] keyHandle, short handleOff, short handleLen, byte[] apduBuffer) {
		Util.arrayCopyNonAtomic(keyHandle, handleOff, apduBuffer, (short) 0, handleLen);
		Util.arrayCopyNonAtomic(pukName, (short) 0, apduBuffer, handleLen, (short) pukName.length);
		if (ThothPGPApplet.api.getObjectMaterial(apduBuffer, (short) 0, handleLen, true, apduBuffer,
				(short) (handleLen + pukName.length), T101OpenAPI.CRED_FIELD_NAME, apduBuffer, handleLen,
				(short) pukName.length, T101OpenAPI.AUTH_INTERNAL) != (short) -1) {
			Util.arrayCopyNonAtomic(apduBuffer, (short) (handleLen + pukName.length), nonceBuffer, (short) 0,
					(short) 8);
			return authContainer(pukUserPin, (short) 0, (short) pukUserPin.length, nonceBuffer, (short) 0, apduBuffer);
		}

		return (short) 0;
	}

	public boolean initEnv(byte[] apduBuffer) {
		boolean isProceed = false;
		Util.arrayFillNonAtomic(apduBuffer, (short) 0, (short) 256, (byte) 0x00);
		apduBuffer[0] = T101OpenAPI.CRED_CLASS_PIN;
		Util.arrayCopyNonAtomic(aocPin, (short) 0, apduBuffer, (short) 1, (short) aocPin.length);
		Util.arrayCopyNonAtomic(appName, (short) 0, apduBuffer, (short) (1 + aocPin.length), (short) appName.length);
		Util.arrayCopyNonAtomic(defaultExpiryTime, (short) 0, apduBuffer, (short) (1 + aocPin.length + appName.length),
				(short) 4);
		isProceed = ThothPGPApplet.api.createAOCContainer(apduBuffer[0], apduBuffer, (short) 1, (short) aocPin.length,
				aocPinMaxRetry, apduBuffer, (short) (1 + aocPin.length), (short) appName.length, apduBuffer,
				(short) (1 + aocPin.length + appName.length));

		// Enroll Admin
		if (isProceed) {
			isProceed = enrollNewAdminUsers(adminName, (short) 0, (short) adminName.length, Constants.ADMIN_PIN_DEFAULT,
					(short) 0, (short) Constants.ADMIN_PIN_DEFAULT.length, defaultExpiryTime, (short) 0, aocPin,
					(short) 0, (short) aocPin.length, apduBuffer);
		}

		// Enroll PUK while using the same Admin PIN as the Admin user.
		if (isProceed) {
			isProceed = enrollNewAdminUsers(pukName, (short) 0, (short) pukName.length, Constants.ADMIN_PIN_DEFAULT,
					(short) 0, (short) Constants.ADMIN_PIN_DEFAULT.length, defaultExpiryTime, (short) 0, aocPin,
					(short) 0, (short) aocPin.length, apduBuffer);
			if (isProceed) {
				JCSystem.beginTransaction();
				pukUserPin = null;
				pukUserPin = new byte[(short) Constants.ADMIN_PIN_DEFAULT.length];
				Util.arrayCopy(Constants.ADMIN_PIN_DEFAULT, (short) 0, pukUserPin, (short) 0,
						(short) Constants.ADMIN_PIN_DEFAULT.length);
				JCSystem.commitTransaction();
			}
		}

		// Finalize container
		if (isProceed) {
			isProceed = finalizeContainer(aocPin, (short) 0, (short) aocPin.length, apduBuffer);
		}

		// Enroll interactive user
		if (isProceed) {
			isProceed = enrollNormalUser(userName, (short) 0, (short) userName.length, Constants.USER_PIN_DEFAULT,
					(short) 0, (short) Constants.USER_PIN_DEFAULT.length, defaultExpiryTime, (short) 0,
					Constants.ADMIN_PIN_DEFAULT, (short) 0, (short) Constants.ADMIN_PIN_DEFAULT.length, apduBuffer);
		}

		return isProceed;
	}

	public boolean destroyEnv() {
		return ThothPGPApplet.api.destroyAOCContainer();
	}

	public short authContainer(byte[] secret, short secOffset, short secLen, byte[] nonce, short nonceOffset,
			byte[] apduBuffer) {
		apduBuffer[0] = MessageDigest.ALG_SHA_256;
		Util.arrayCopyNonAtomic(secret, secOffset, apduBuffer, (short) 1, secLen);
		Util.arrayCopyNonAtomic(nonce, nonceOffset, apduBuffer, (short) (1 + secLen), (short) 8);

		ThothPGPApplet.api.cryptoHMAC(apduBuffer[0], // hashType
				apduBuffer, (short) 1, secLen, // key
				apduBuffer, (short) (1 + secLen), (short) 8, // nonce
				apduBuffer, (short) (9 + secLen), // ipad
				apduBuffer, (short) (73 + secLen), // opad
				apduBuffer, (short) (137 + secLen), // secBuff
				apduBuffer, (short) 201); // output

		// Call extendedRequest to submit final signed nonce result
		return ThothPGPApplet.api.extendedRequest(apduBuffer, (short) 201, (short) 32, apduBuffer, (short) 0);
	}

	public boolean finalizeContainer(byte[] aocPin, short aocPinOffset, short aocPinLen, byte[] apduBuffer) {
		if (ThothPGPApplet.api.finalizeNewContainer(apduBuffer, (short) 0)) {
			Util.arrayCopyNonAtomic(apduBuffer, (short) 0, nonceBuffer, (short) 0, (short) 8);
			if (authContainer(aocPin, aocPinOffset, aocPinLen, nonceBuffer, (short) 0, apduBuffer) == 1) {
				return true;
			}
		}

		return false;
	}

	public boolean enrollNewAdminUsers(byte[] adminUser, short adminUserOffset, short adminUserLen, byte[] adminPin,
			short adminPinOffset, short adminPinLen, byte[] expiryTime, short expiryTimeOffset, byte[] aocPin,
			short aocPinOffset, short aocPinLen, byte[] apduBuffer) {
		apduBuffer[0] = T101OpenAPI.CRED_CLASS_PIN;
		apduBuffer[1] = T101OpenAPI.CRED_MGMT_FRONT_PANEL;
		Util.arrayCopyNonAtomic(adminPin, adminPinOffset, apduBuffer, (short) 2, adminPinLen);
		Util.arrayCopyNonAtomic(adminUser, adminUserOffset, apduBuffer, (short) (2 + adminPinLen), adminUserLen);
		Util.arrayCopyNonAtomic(expiryTime, expiryTimeOffset, apduBuffer, (short) (2 + adminPinLen + adminUserLen),
				(short) 4);
		if (ThothPGPApplet.api.newAOCUserCred(apduBuffer[0], apduBuffer, (short) 2, (short) adminPinLen, (short) 3,
				apduBuffer, (short) (2 + adminPinLen), (short) adminUserLen, apduBuffer,
				(short) (2 + adminPinLen + adminUserLen), T101OpenAPI.CRED_FIELD_NAME, null, (short) 0, (short) 0,
				T101OpenAPI.AUTH_INTERNAL, apduBuffer, (short) (6 + adminPinLen + adminUserLen))) {
			if (authContainer(aocPin, aocPinOffset, aocPinLen, apduBuffer, (short) (6 + adminPinLen + adminUserLen),
					apduBuffer) == 1) {
				return true;
			} else {
				ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0x15));
			}
		} else {
			ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0x14));
		}

		return false;
	}

	public boolean enrollNormalUser(byte[] username, short offset, short len, byte[] userPin, short pinOffset,
			short pinLen, byte[] expiryTime, short expiryTimeOffset, byte[] adminPin, short adminPinOffset,
			short adminPinLen, byte[] apduBuffer) {
		apduBuffer[0] = T101OpenAPI.CRED_CLASS_PIN;
		apduBuffer[1] = T101OpenAPI.CRED_MGMT_FRONT_PANEL;
		Util.arrayCopyNonAtomic(userPin, pinOffset, apduBuffer, (short) 2, pinLen);
		Util.arrayCopyNonAtomic(username, offset, apduBuffer, (short) (2 + pinLen), len);
		Util.arrayCopyNonAtomic(expiryTime, expiryTimeOffset, apduBuffer, (short) (2 + pinLen + len), (short) 4);
		Util.arrayCopyNonAtomic(adminName, (short) 0, apduBuffer, (short) (6 + pinLen + len), (short) adminName.length);
		if (ThothPGPApplet.api.newAOCUserCred(apduBuffer[0], apduBuffer, (short) 2, (short) pinLen, (short) 3,
				apduBuffer, (short) (2 + pinLen), (short) len, apduBuffer, (short) (2 + pinLen + len),
				T101OpenAPI.CRED_FIELD_NAME, apduBuffer, (short) (6 + pinLen + len), (short) adminName.length,
				T101OpenAPI.AUTH_INTERNAL, apduBuffer, (short) (6 + pinLen + len + adminName.length))) {
			Util.arrayCopyNonAtomic(apduBuffer, (short) (6 + pinLen + len + adminName.length), nonceBuffer, (short) 0,
					(short) 8);
			if (authContainer(adminPin, adminPinOffset, adminPinLen, nonceBuffer, (short) 0, apduBuffer) == 1) {
				return true;
			} else {
				ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0x17));
			}
		} else {
			ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0x16));
		}

		return false;
	}

	public short loginNormalUserAndGetTries(byte[] apduBuffer) {
		if (confirmationUI(TXT_LOGIN_USR_TITLE, (short) 0, (short) TXT_LOGIN_USR_TITLE.length, TXT_LOGIN, (short) 0,
				(short) TXT_LOGIN.length, apduBuffer)) {
			Util.arrayCopyNonAtomic(userName, (short) 0, apduBuffer, (short) 0, (short) userName.length);
			return ThothPGPApplet.api.getUserInfo(T101OpenAPI.CRED_FIELD_NAME, apduBuffer, (short) 0,
					(short) userName.length, T101OpenAPI.CRED_FIELD_NAME, apduBuffer, (short) 0,
					(short) userName.length, T101OpenAPI.CRED_FIELD_MAX_RETRIES, apduBuffer, (short) 0,
					T101OpenAPI.AUTH_FRONTPANEL);
		}
		return (short) -1;
	}

	public short loginAdminUserAndGetTries(byte[] apduBuffer) {
		if (confirmationUI(TXT_LOGIN_ADM_TITLE, (short) 0, (short) TXT_LOGIN_ADM_TITLE.length, TXT_LOGIN, (short) 0,
				(short) TXT_LOGIN.length, apduBuffer)) {
			Util.arrayCopyNonAtomic(adminName, (short) 0, apduBuffer, (short) 0, (short) adminName.length);
			return ThothPGPApplet.api.getUserInfo(T101OpenAPI.CRED_FIELD_NAME, apduBuffer, (short) 0,
					(short) adminName.length, T101OpenAPI.CRED_FIELD_NAME, apduBuffer, (short) 0,
					(short) adminName.length, T101OpenAPI.CRED_FIELD_MAX_RETRIES, apduBuffer, (short) 0,
					T101OpenAPI.AUTH_FRONTPANEL);
		}
		return (short) -1;
	}

	public boolean adminResetNormalUserPin(byte[] apduBuffer) {
		tempBuf = null;
		boolean isSuccess = false;

		// Use UX Render to accept new normal user pin
		short secLen = uxRender(T101OpenAPI.UI_TYPE_INPUT, (byte) 0x01, (byte) 0x01, (byte) 0xFF, (byte) 0x20,
				TXT_CHANGE_PIN_TITLE, (short) 0, (short) TXT_CHANGE_PIN_TITLE.length, TXT_NEW_PIN, (short) 0,
				(short) TXT_NEW_PIN.length, aocPin, (short) 0, (short) aocPin.length, apduBuffer);

		if (secLen >= 2) {
			tempBuf = new byte[secLen];
			Util.arrayCopyNonAtomic(apduBuffer, (short) 0, tempBuf, (short) 0, secLen);
			Util.arrayCopyNonAtomic(tempBuf, (short) 0, apduBuffer, (short) 0, secLen);
			tempBuf = null;
			Util.arrayCopyNonAtomic(userName, (short) 0, apduBuffer, secLen, (short) userName.length);
			Util.arrayCopyNonAtomic(adminName, (short) 0, apduBuffer, (short) (secLen + userName.length),
					(short) adminName.length);
			isSuccess = ThothPGPApplet.api.resetAOCUserCred(apduBuffer, (short) 0, secLen, apduBuffer, secLen,
					(short) userName.length, T101OpenAPI.CRED_FIELD_NAME, apduBuffer,
					(short) (secLen + userName.length), (short) adminName.length, T101OpenAPI.AUTH_FRONTPANEL, null,
					(short) 0);
			Util.arrayFillNonAtomic(apduBuffer, (short) 0, (short) (secLen + userName.length + adminName.length),
					(byte) 0x00);
		}

		opsStatusUI(isSuccess, TXT_CHANGE_PIN_TITLE, (short) 0, (short) TXT_CHANGE_PIN_TITLE.length, apduBuffer);

		return isSuccess;
	}

	public boolean pukResetNormalUserPin(byte[] apduBuffer) {
		tempBuf = null;
		boolean isSuccess = false;

		// Use UX Render to accept new normal user pin
		short secLen = uxRender(T101OpenAPI.UI_TYPE_INPUT, (byte) 0x01, (byte) 0x01, (byte) 0xFF, (byte) 0x20,
				TXT_CHANGE_PIN_TITLE, (short) 0, (short) TXT_CHANGE_PIN_TITLE.length, TXT_NEW_PIN, (short) 0,
				(short) TXT_NEW_PIN.length, aocPin, (short) 0, (short) aocPin.length, apduBuffer);

		if (secLen >= 2) {
			tempBuf = new byte[secLen];
			Util.arrayCopyNonAtomic(apduBuffer, (short) 0, tempBuf, (short) 0, secLen);
			Util.arrayCopyNonAtomic(tempBuf, (short) 0, apduBuffer, (short) 0, secLen);
			tempBuf = null;
			Util.arrayCopyNonAtomic(userName, (short) 0, apduBuffer, secLen, (short) userName.length);
			Util.arrayCopyNonAtomic(pukName, (short) 0, apduBuffer, (short) (secLen + userName.length),
					(short) pukName.length);
			isSuccess = ThothPGPApplet.api.resetAOCUserCred(apduBuffer, (short) 0, secLen, apduBuffer, secLen,
					(short) userName.length, T101OpenAPI.CRED_FIELD_NAME, apduBuffer,
					(short) (secLen + userName.length), (short) pukName.length, T101OpenAPI.AUTH_FRONTPANEL, null,
					(short) 0);
			Util.arrayFillNonAtomic(apduBuffer, (short) 0, (short) (secLen + userName.length + pukName.length),
					(byte) 0x00);
		}

		opsStatusUI(isSuccess, TXT_CHANGE_PIN_TITLE, (short) 0, (short) TXT_CHANGE_PIN_TITLE.length, apduBuffer);

		return isSuccess;
	}

	public boolean changeNormalUserPin(byte[] apduBuffer) {
		boolean isSuccess = false;

		// Use UX Render to accept new PIN
		short len = uxRender(T101OpenAPI.UI_TYPE_INPUT, (byte) 0x01, (byte) 0x01, (byte) 0xFF, (byte) 0x20,
				TXT_CHANGE_PIN_TITLE, (short) 0, (short) TXT_CHANGE_PIN_TITLE.length, TXT_NEW_PIN, (short) 0,
				(short) TXT_NEW_PIN.length, aocPin, (short) 0, (short) aocPin.length, apduBuffer);

		if (len >= 2) {
			Util.arrayCopyNonAtomic(userName, (short) 0, apduBuffer, len, (short) userName.length);
			isSuccess = ThothPGPApplet.api.manageUserCred(T101OpenAPI.CRED_FIELD_SECRET, apduBuffer, (short) 0, len,
					null, (short) 0, T101OpenAPI.CRED_FIELD_NAME, apduBuffer, len, (short) userName.length,
					T101OpenAPI.AUTH_FRONTPANEL);
			Util.arrayFillNonAtomic(apduBuffer, (short) 0, len, (byte) 0x00);
		}

		opsStatusUI(isSuccess, TXT_CHANGE_PIN_TITLE, (short) 0, (short) TXT_CHANGE_PIN_TITLE.length, apduBuffer);

		return isSuccess;
	}

	public boolean changeAdminPin(byte[] apduBuffer) {
		boolean isSuccess = false;

		// Use UX Render to accept new PIN
		short len = uxRender(T101OpenAPI.UI_TYPE_INPUT, (byte) 0x01, (byte) 0x01, (byte) 0xFF, (byte) 0x20,
				TXT_CHANGE_PIN_TITLE, (short) 0, (short) TXT_CHANGE_PIN_TITLE.length, TXT_NEW_PIN, (short) 0,
				(short) TXT_NEW_PIN.length, aocPin, (short) 0, (short) aocPin.length, apduBuffer);

		if (len >= 2) {
			Util.arrayCopyNonAtomic(adminName, (short) 0, apduBuffer, len, (short) adminName.length);
			isSuccess = ThothPGPApplet.api.manageUserCred(T101OpenAPI.CRED_FIELD_SECRET, apduBuffer, (short) 0, len,
					null, (short) 0, T101OpenAPI.CRED_FIELD_NAME, apduBuffer, len, (short) adminName.length,
					T101OpenAPI.AUTH_FRONTPANEL);
			Util.arrayFillNonAtomic(apduBuffer, (short) 0, len, (byte) 0x00);
		}

		opsStatusUI(isSuccess, TXT_CHANGE_PIN_TITLE, (short) 0, (short) TXT_CHANGE_PIN_TITLE.length, apduBuffer);

		return isSuccess;
	}

	public boolean pukChangePUKPinPin(byte[] apduBuffer) {
		tempBuf = null;
		boolean isSuccess = false;

		// Use UX Render to accept new PIN
		short secLen = uxRender(T101OpenAPI.UI_TYPE_INPUT, (byte) 0x01, (byte) 0x01, (byte) 0xFF, (byte) 0x20,
				TXT_CHANGE_PIN_TITLE, (short) 0, (short) TXT_CHANGE_PIN_TITLE.length, TXT_NEW_PIN, (short) 0,
				(short) TXT_NEW_PIN.length, aocPin, (short) 0, (short) aocPin.length, apduBuffer);

		if (secLen >= 2) {
			tempBuf = new byte[secLen];
			Util.arrayCopyNonAtomic(apduBuffer, (short) 0, tempBuf, (short) 0, secLen);
			Util.arrayCopyNonAtomic(pukName, (short) 0, apduBuffer, secLen, (short) pukName.length);
			if (ThothPGPApplet.api.manageUserCred(T101OpenAPI.CRED_FIELD_SECRET, apduBuffer, (short) 0, secLen,
					apduBuffer, (short) 0, T101OpenAPI.CRED_FIELD_NAME, apduBuffer, secLen, (short) pukName.length,
					T101OpenAPI.AUTH_INTERNAL)) {
				Util.arrayCopyNonAtomic(apduBuffer, (short) 0, nonceBuffer, (short) 0, (short) 8);
				if (authContainer(pukUserPin, (short) 0, (short) pukUserPin.length, nonceBuffer, (short) 0,
						apduBuffer) != (short) -1) {
					JCSystem.beginTransaction();
					pukUserPin = null;
					pukUserPin = new byte[secLen];
					Util.arrayCopyNonAtomic(tempBuf, (short) 0, pukUserPin, (short) 0, secLen);
					JCSystem.commitTransaction();
					tempBuf = null;
					isSuccess = true;
				}
			}
		}
		Util.arrayFillNonAtomic(apduBuffer, (short) 0, secLen, (byte) 0x00);
		tempBuf = null;

		opsStatusUI(isSuccess, TXT_CHANGE_PIN_TITLE, (short) 0, (short) TXT_CHANGE_PIN_TITLE.length, apduBuffer);

		return isSuccess;
	}

	public boolean newAsymmetricKeyObject(byte asymType, byte ind, byte[] expiryTS, short expiryOffset, byte[] buffer) {
		short nameLen = 4;
		Util.arrayCopyNonAtomic(getKeyHandle(ind), (short) 0, buffer, (short) 0, nameLen);
		Util.arrayCopyNonAtomic(expiryTS, expiryOffset, buffer, nameLen, (short) 4);
		Util.arrayCopyNonAtomic(pukName, (short) 0, buffer, (short) (4 + nameLen), (short) pukName.length);
		buffer[(short) (4 + nameLen + pukName.length)] = asymType;
		buffer[(short) (5 + nameLen + pukName.length)] = (byte) 0x07;

		if (ThothPGPApplet.api.newObject(T101OpenAPI.OBJ_TYPE_KEY, // objectType
				buffer, (short) 0, nameLen, // objectName
				null, (short) 0, (short) 0, // om1
				null, (short) 0, (short) 0, // om2
				T101OpenAPI.OBJ_PERM_EXPORT_ALLOW_FLAG, // export
				buffer[(short) (5 + nameLen + pukName.length)], // acl
				T101OpenAPI.KEY_CLASS_ASYMMETRIC, // keyClass
				buffer[(short) (4 + nameLen + pukName.length)], // keyType
				true, // requireAttestation
				buffer, nameLen, // expiry
				T101OpenAPI.CRED_FIELD_NAME, buffer, (short) (4 + nameLen), (short) pukName.length, // authUserCred
				buffer, (short) (6 + nameLen + pukName.length), // output
				T101OpenAPI.AUTH_INTERNAL) // authMethod
		) {
			Util.arrayCopyNonAtomic(buffer, (short) (6 + nameLen + pukName.length), nonceBuffer, (short) 0, (short) 8);
			if (authContainer(pukUserPin, (short) 0, (short) pukUserPin.length, nonceBuffer, (short) 0,
					buffer) != (short) -1) {
				return true;
			}
		}

		return false;
	}

	public short executeObject(byte execMethod, byte subOpMode1, byte subOpMode2, boolean useBufferedData, byte ind,
			byte[] input, short offset, short len, byte[] buffer) {
		short nameLen = 4;
		short result = (short) -1;

		Util.arrayCopyNonAtomic(getKeyHandle(ind), (short) 0, buffer, (short) 0, nameLen);

		if (input != null) {
			Util.arrayCopyNonAtomic(input, offset, buffer, nameLen, len);
		}

		Util.arrayCopyNonAtomic(pukName, (short) 0, buffer, (short) (nameLen + len), (short) pukName.length);

		result = ThothPGPApplet.api.executeObject(execMethod, // execMethod
				subOpMode1, // subOpMode1
				subOpMode2, // subOpMode2
				useBufferedData, // useBufferData
				buffer, (short) 0, nameLen, // objectName
				buffer, nameLen, len, // input
				buffer, (short) (nameLen + len + pukName.length), // output
				KM101.T101OpenAPI.CRED_FIELD_NAME, buffer, (short) (nameLen + len), (short) pukName.length, // authUserCred
				KM101.T101OpenAPI.AUTH_INTERNAL // authMethod
		);

		if (result != (short) -1) {
			Util.arrayCopyNonAtomic(buffer, (short) (nameLen + len + pukName.length), nonceBuffer, (short) 0,
					(short) 8);
			return authContainer(pukUserPin, (short) 0, (short) pukUserPin.length, nonceBuffer, (short) 0, buffer);
		}

		return result;
	}

	public short getObjectCreationTS(byte ind , byte[] buffer) {
		short nameLen = 4;
		
		// Copy object handle name into buffer for API call
		Util.arrayCopyNonAtomic(getKeyHandle(ind), (short) 0, buffer, (short) 0, nameLen);
		
		// Copy PUK username into buffer for API call
		Util.arrayCopyNonAtomic(pukName, (short) 0, buffer, (short) nameLen, (short) pukName.length);

		if (ThothPGPApplet.api.getObjectInfo(buffer, (short) 0, nameLen, T101OpenAPI.OBJ_FIELD_CREATE, buffer,
				(short) (nameLen + pukName.length), T101OpenAPI.CRED_FIELD_NAME, buffer, (short) nameLen,
				(short) pukName.length, KM101.T101OpenAPI.AUTH_INTERNAL) != (short) -1) {
			Util.arrayCopyNonAtomic(buffer, (short) (nameLen + pukName.length), nonceBuffer, (short) 0, (short) 8);
			return authContainer(pukUserPin, (short) 0, (short) pukUserPin.length, nonceBuffer, (short) 0, buffer);
		}

		return (short) -1;
	}

	public boolean destroyObject(byte[] objName, short offset, short len, byte[] buffer) {
		Util.arrayCopyNonAtomic(pukName, (short) 0, buffer, len, (short) pukName.length);
		if (ThothPGPApplet.api.deleteObject(buffer, (short) 0, len, buffer, (short) (len + pukName.length),
				KM101.T101OpenAPI.CRED_FIELD_NAME, buffer, len, (short) pukName.length,
				KM101.T101OpenAPI.AUTH_INTERNAL)) {
			// Session auth nonce
			Util.arrayCopyNonAtomic(buffer, (short) (len + pukName.length), nonceBuffer, (short) 0, (short) 8);

			// Authenticate against auth nonce
			if (authContainer(pukUserPin, (short) 0, (short) pukUserPin.length, nonceBuffer, (short) 0,
					buffer) != (short) -1) {
				return true;
			}
		}
		return false;
	}

	public boolean confirmationUI(byte[] title, short titleOffset, short titleLen, byte[] input, short inOffset,
			short inLen, byte[] apduBuffer) {
		if (uxRender(T101OpenAPI.UI_TYPE_TEXT, T101OpenAPI.NULL, T101OpenAPI.NULL, T101OpenAPI.NULL, T101OpenAPI.NULL,
				title, titleOffset, titleLen, input, inOffset, inLen, aocPin, (short) 0, (short) aocPin.length,
				apduBuffer) == (short) 1) {
			return true;
		}

		return false;
	}

	public void opsStatusUI(boolean isSuccess, byte[] title, short titleOffset, short titleLen, byte[] apduBuffer) {
		if (isSuccess) {
			uxRender(T101OpenAPI.UI_TYPE_TEXT, T101OpenAPI.NULL, T101OpenAPI.NULL, T101OpenAPI.NULL, T101OpenAPI.NULL,
					title, titleOffset, titleLen, TXT_SUCCESS, (short) 0, (short) TXT_SUCCESS.length, aocPin, (short) 0,
					(short) aocPin.length, apduBuffer);
		} else {
			uxRender(T101OpenAPI.UI_TYPE_TEXT, T101OpenAPI.NULL, T101OpenAPI.NULL, T101OpenAPI.NULL, T101OpenAPI.NULL,
					title, titleOffset, titleLen, TXT_FAILED, (short) 0, (short) TXT_FAILED.length, aocPin, (short) 0,
					(short) aocPin.length, apduBuffer);
		}
	}

	public short uxRender(byte type, byte subMode, byte subMode1, byte subMode2, byte subMode3, byte[] title,
			short titleOffset, short titleLen, byte[] input, short inOffset, short inLen, byte[] aocPin,
			short aocPinOffset, short aocPinLen, byte[] apduBuffer) {
		apduBuffer[0] = type;
		short snonceBuffer = (short) 0;
		short sb1 = (short) 0;
		short sb2 = (short) 0;
		if (title != null && titleLen > 0) {
			Util.arrayCopyNonAtomic(title, titleOffset, apduBuffer, (short) 1, titleLen);
			sb1 = titleLen;
		}

		if (input != null && inLen > 0) {
			Util.arrayCopyNonAtomic(input, inOffset, apduBuffer, (short) (1 + sb1), inLen);
			sb2 = inLen;
		}

		snonceBuffer = ThothPGPApplet.api.uiSession(apduBuffer[0], subMode, subMode1, subMode2, subMode3, apduBuffer,
				(short) 1, sb1, apduBuffer, (short) (1 + sb1), sb2, apduBuffer, (short) (1 + sb1 + sb2));
		if (snonceBuffer != -1) {
			Util.arrayCopyNonAtomic(apduBuffer, (short) (1 + sb1 + sb2), nonceBuffer, (short) 0, (short) 8);
			snonceBuffer = authContainer(aocPin, aocPinOffset, aocPinLen, nonceBuffer, (short) 0, apduBuffer);
			if (snonceBuffer > -1) {
				return snonceBuffer;
			} else {
				ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0xc2));
			}
		} else {
			ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0xc1));
		}
		return (short) -1;
	}

	public boolean clearUploadBuffer(byte[] buffer) {
		if (ThothPGPApplet.api.clearBuffer(buffer, (short) 0) != (short) -1) {
			// Session auth nonce
			Util.arrayCopyNonAtomic(buffer, (short) 0, nonceBuffer, (short) 0, (short) 8);

			// Authenticate against auth nonce
			if (authContainer(aocPin, (short) 0, (short) aocPin.length, nonceBuffer, (short) 0, buffer) != (short) -1) {
				return true;
			}
		}
		return false;
	}

	public boolean uploadToBuffer(boolean isAppend, short maxLen, byte[] input, short offset, short len,
			byte[] buffer) {
		Util.arrayCopyNonAtomic(input, offset, buffer, (short) 0, len);
		short sb0 = (short) 0;
		if (isAppend) {
			// Append to existing buffer with buffer offset since the last entry length
			sb0 = ThothPGPApplet.api.bufferData(true, (short) 0, buffer, (short) 0, len, getBufferLength(), buffer,
					len);
		} else {
			// New buffer
			sb0 = ThothPGPApplet.api.bufferData(true, maxLen, buffer, (short) 0, len, (short) 0, buffer, len);
		}
		if (sb0 != (short) -1) {
			// Session auth nonce
			Util.arrayCopyNonAtomic(buffer, len, nonceBuffer, (short) 0, (short) 8);

			// Authenticate against auth nonce
			if (authContainer(aocPin, (short) 0, (short) aocPin.length, nonceBuffer, (short) 0, buffer) != (short) -1) {
				return true;
			}
		}
		return false;
	}

	public short readFromBuffer(short readOff, short readLen, byte[] buffer) {
		if (ThothPGPApplet.api.bufferData(false, (short) 0, null, (short) 0, readLen, readOff, buffer,
				(short) 0) != (short) -1) {
			// Session auth nonce
			Util.arrayCopyNonAtomic(buffer, (short) 0, nonceBuffer, (short) 0, (short) 8);

			// Authenticate against auth nonce
			return authContainer(aocPin, (short) 0, (short) aocPin.length, nonceBuffer, (short) 0, buffer);
		}
		return (short) -1;
	}

	public short getBufferLength() {
		return ThothPGPApplet.api.getBufferDataLength();
	}

	public boolean writeCert(byte ind, byte[] cert, short inOff, short storeOff, short len) {
		// Load input into certificate store
		short uploadSize = (short) 0;
		for (short i = 0; i < len;) {
			if ((short) (len - i) > (short) 261) {
				uploadSize = (short) 261;
			} else {
				uploadSize = (short) (len - i);
			}

			if (!ThothPGPApplet.csapi.writeCert(ind, cert, (short) (inOff + i), (short) (storeOff + i), uploadSize)) {
				return false;
			}
			i += uploadSize;
		}
		return true;
	}

	public short readCert(byte ind, byte[] output, short outOff, short storeOff, short len) {
		short readSize = (short) 0;
		short i = (short) 0;
		for (; i < len;) {
			if ((short) (len - i) > (short) 261) {
				readSize = (short) 261;
			} else {
				readSize = (short) (len - i);
			}
			if (ThothPGPApplet.csapi.readCert(ind, output, (short) (outOff + i), (short) (storeOff + i),
					readSize) != (short) -1) {
				return (short) -1;
			}
			i += readSize;
		}
		return i;
	}

	public void clearCert(byte ind) {
		ThothPGPApplet.csapi.clearCert(ind);
	}

	public short certLength(byte ind) {
		return ThothPGPApplet.csapi.certLength(ind);
	}

	public static void shortToBytes(short s, byte[] b, short offset) {
		b[offset] = (byte) ((s >> 8) & 0xFF);
		b[(short) (offset + 1)] = (byte) (s & 0xFF);
	}
}
