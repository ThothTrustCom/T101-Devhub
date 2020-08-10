package thetapass;

import KM101.T101OpenAPI;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;

public class APIShim {
	private byte[] aocPin;
	private byte[] nonceBuffer = JCSystem.makeTransientByteArray((short) 8, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
	public static final byte[] appName = { (byte) 0x54, (byte) 0x48, (byte) 0x45, (byte) 0x54, (byte) 0x41, (byte) 0x50,
			(byte) 0x41, (byte) 0x53, (byte) 0x53 };
	public static final byte[] defaultExpiryTime = new byte[4];
	private short aocPinMaxRetry = 5;
	private byte[] tempBuf = null;

	public static final byte[] TXT_CCODE = { (byte) 0x4f, (byte) 0x54, (byte) 0x50, (byte) 0x20, (byte) 0x43,
			(byte) 0x6f, (byte) 0x64, (byte) 0x65 };
	public static final byte[] TXT_PROMPT_OKC = { (byte) 0x50, (byte) 0x72, (byte) 0x65, (byte) 0x73, (byte) 0x73,
			(byte) 0x20, (byte) 0x4f, (byte) 0x4b, (byte) 0x2f, (byte) 0x43 };
	public static final byte[] TXT_SECURE_SESS = { (byte) 0x53, (byte) 0x45, (byte) 0x43, (byte) 0x20, (byte) 0x53,
			(byte) 0x45, (byte) 0x53, (byte) 0x53, (byte) 0x4e };
//	public static final byte[] TXT_CHANGE_PIN_TITLE = { (byte) 0x55, (byte) 0x70, (byte) 0x64, (byte) 0x74, (byte) 0x65,
//			(byte) 0x20, (byte) 0x50, (byte) 0x49, (byte) 0x4e };
//	public static final byte[] TXT_CHANGE_PIN_STITLE = { (byte) 0x55, (byte) 0x70, (byte) 0x64, (byte) 0x61,
//			(byte) 0x74, (byte) 0x65, (byte) 0x20, (byte) 0x50, (byte) 0x69, (byte) 0x6e, (byte) 0x20, (byte) 0x23,
//			(byte) 0x30, (byte) 0x3a };
//	public static final byte[] TXT_RESET_PIN_TITLE = { (byte) 0x52, (byte) 0x65, (byte) 0x73, (byte) 0x65, (byte) 0x74,
//			(byte) 0x20, (byte) 0x50, (byte) 0x49, (byte) 0x4e };
//	public static final byte[] TXT_RESET_PIN_STITLE = { (byte) 0x52, (byte) 0x65, (byte) 0x73, (byte) 0x65, (byte) 0x74,
//			(byte) 0x20, (byte) 0x50, (byte) 0x49, (byte) 0x4e, (byte) 0x20, (byte) 0x23, (byte) 0x30, (byte) 0x3a };
//	public static final byte[] TXT_NEW_PIN_TITLE = { (byte) 0x4e, (byte) 0x65, (byte) 0x77, (byte) 0x20, (byte) 0x50,
//			(byte) 0x49, (byte) 0x4e };
//	public static final byte[] TXT_NEW_PIN_STITLE = { (byte) 0x4e, (byte) 0x65, (byte) 0x77, (byte) 0x20, (byte) 0x50,
//			(byte) 0x49, (byte) 0x4e, (byte) 0x20, (byte) 0x23, (byte) 0x30, (byte) 0x3a };
//	public static final byte[] TXT_NEW_PUK_TITLE = { (byte) 0x4e, (byte) 0x65, (byte) 0x77, (byte) 0x20, (byte) 0x50,
//			(byte) 0x55, (byte) 0x4b };
//	public static final byte[] TXT_NEW_PUK_STITLE = { (byte) 0x4e, (byte) 0x65, (byte) 0x77, (byte) 0x20, (byte) 0x50,
//			(byte) 0x55, (byte) 0x4b, (byte) 0x20, (byte) 0x23, (byte) 0x30, (byte) 0x3a };
	public static final byte[] TXT_SUCCESS = new byte[] { (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x4f,
			(byte) 0x70, (byte) 0x65, (byte) 0x72, (byte) 0x61, (byte) 0x74, (byte) 0x69, (byte) 0x6f, (byte) 0x6e,
			(byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20,
			(byte) 0x53, (byte) 0x75, (byte) 0x63, (byte) 0x63, (byte) 0x65, (byte) 0x73, (byte) 0x73 };
	public static final byte[] TXT_FAILED = new byte[] { (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x4f,
			(byte) 0x70, (byte) 0x65, (byte) 0x72, (byte) 0x61, (byte) 0x74, (byte) 0x69, (byte) 0x6f, (byte) 0x6e,
			(byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20,
			(byte) 0x46, (byte) 0x61, (byte) 0x69, (byte) 0x6c, (byte) 0x65, (byte) 0x64 };
	public static final byte[] TXT_CANCELLED = new byte[] { (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x4f,
			(byte) 0x70, (byte) 0x65, (byte) 0x72, (byte) 0x61, (byte) 0x74, (byte) 0x69, (byte) 0x6f, (byte) 0x6e,
			(byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x43,
			(byte) 0x61, (byte) 0x61, (byte) 0x6e, (byte) 0x63, (byte) 0x65, (byte) 0x6c, (byte) 0x6c, (byte) 0x65,
			(byte) 0x64 };
//	public static final byte[] TXT_CRYPT_OPS_TITLE = new byte[] { (byte) 0x43, (byte) 0x72, (byte) 0x79, (byte) 0x70,
//			(byte) 0x74, (byte) 0x20, (byte) 0x4f, (byte) 0x70, (byte) 0x73 };
//	public static final byte[] TXT_SIG_OPS_TITLE = new byte[] { (byte) 0x53, (byte) 0x69, (byte) 0x67, (byte) 0x6e,
//			(byte) 0x20, (byte) 0x55, (byte) 0x6e, (byte) 0x6b, (byte) 0x6e };
//	public static final byte[] TXT_SEND_TXN_TITLE = new byte[] { (byte) 0x53, (byte) 0x65, (byte) 0x6e, (byte) 0x64,
//			(byte) 0x20, (byte) 0x54, (byte) 0x78, (byte) 0x6e };
//	public static final byte[] TXT_CRYPT_OPS = { (byte) 0x50, (byte) 0x72, (byte) 0x65, (byte) 0x73, (byte) 0x73,
//			(byte) 0x20, (byte) 0x4f, (byte) 0x4b, (byte) 0x20, (byte) 0x74, (byte) 0x6f, (byte) 0x20, (byte) 0x64,
//			(byte) 0x65, (byte) 0x63, (byte) 0x72, (byte) 0x79, (byte) 0x70, (byte) 0x74, (byte) 0x20, (byte) 0x64,
//			(byte) 0x61, (byte) 0x74, (byte) 0x61, (byte) 0x20, (byte) 0x6f, (byte) 0x72, (byte) 0x20, (byte) 0x43,
//			(byte) 0x20, (byte) 0x74, (byte) 0x6f, (byte) 0x20, (byte) 0x61, (byte) 0x62, (byte) 0x6f, (byte) 0x72,
//			(byte) 0x74, (byte) 0x2e };
//	public static final byte[] TXT_SIG_OPS = { (byte) 0x50, (byte) 0x72, (byte) 0x65, (byte) 0x73, (byte) 0x73,
//			(byte) 0x20, (byte) 0x4f, (byte) 0x4b, (byte) 0x20, (byte) 0x74, (byte) 0x6f, (byte) 0x20, (byte) 0x73,
//			(byte) 0x69, (byte) 0x67, (byte) 0x6e, (byte) 0x20, (byte) 0x64, (byte) 0x61, (byte) 0x74, (byte) 0x61,
//			(byte) 0x20, (byte) 0x6f, (byte) 0x72, (byte) 0x20, (byte) 0x43, (byte) 0x20, (byte) 0x74, (byte) 0x6f,
//			(byte) 0x20, (byte) 0x61, (byte) 0x62, (byte) 0x6f, (byte) 0x72, (byte) 0x74, (byte) 0x2e };
//	public static final byte[] TXT_SEND_TXN_OPS = { (byte) 0x50, (byte) 0x72, (byte) 0x65, (byte) 0x73, (byte) 0x73,
//			(byte) 0x20, (byte) 0x4f, (byte) 0x4b, (byte) 0x20, (byte) 0x74, (byte) 0x6f, (byte) 0x20, (byte) 0x73,
//			(byte) 0x65, (byte) 0x6e, (byte) 0x64, (byte) 0x20, (byte) 0x74, (byte) 0x78, (byte) 0x6e, (byte) 0x20,
//			(byte) 0x6f, (byte) 0x72, (byte) 0x20, (byte) 0x43, (byte) 0x20, (byte) 0x74, (byte) 0x6f, (byte) 0x20,
//			(byte) 0x61, (byte) 0x62, (byte) 0x6f, (byte) 0x72, (byte) 0x74, (byte) 0x2e };
//	public static final byte[] TXT_LOGIN_PUK_TITLE = { (byte) 0x4c, (byte) 0x6f, (byte) 0x67, (byte) 0x69, (byte) 0x6e,
//			(byte) 0x20, (byte) 0x50, (byte) 0x55, (byte) 0x4B };
//	public static final byte[] TXT_LOGIN_USR_TITLE = { (byte) 0x4c, (byte) 0x6f, (byte) 0x67, (byte) 0x69, (byte) 0x6e,
//			(byte) 0x20, (byte) 0x55, (byte) 0x73, (byte) 0x72 };
//	public static final byte[] TXT_LOGIN = { (byte) 0x50, (byte) 0x72, (byte) 0x65, (byte) 0x73, (byte) 0x73,
//			(byte) 0x20, (byte) 0x4f, (byte) 0x4b, (byte) 0x20, (byte) 0x74, (byte) 0x6f, (byte) 0x20, (byte) 0x6c,
//			(byte) 0x6f, (byte) 0x67, (byte) 0x69, (byte) 0x6e, (byte) 0x20, (byte) 0x6f, (byte) 0x72, (byte) 0x20,
//			(byte) 0x43, (byte) 0x20, (byte) 0x74, (byte) 0x6f, (byte) 0x20, (byte) 0x61, (byte) 0x62, (byte) 0x6f,
//			(byte) 0x72, (byte) 0x74, (byte) 0x2e };
//	public static final byte[] TXT_RESET_CARD = { (byte) 0x50, (byte) 0x72, (byte) 0x65, (byte) 0x73, (byte) 0x73,
//			(byte) 0x20, (byte) 0x4f, (byte) 0x4b, (byte) 0x20, (byte) 0x74, (byte) 0x6f, (byte) 0x20, (byte) 0x72,
//			(byte) 0x65, (byte) 0x73, (byte) 0x65, (byte) 0x74, (byte) 0x20, (byte) 0x63, (byte) 0x61, (byte) 0x72,
//			(byte) 0x64, (byte) 0x20, (byte) 0x6f, (byte) 0x72, (byte) 0x20, (byte) 0x43, (byte) 0x20, (byte) 0x74,
//			(byte) 0x6f, (byte) 0x20, (byte) 0x63, (byte) 0x61, (byte) 0x6e, (byte) 0x63, (byte) 0x65, (byte) 0x6c,
//			(byte) 0x2e };
//	public static final byte[] TXT_LOGIN_STITLE = { (byte) 0x4c, (byte) 0x6f, (byte) 0x67, (byte) 0x69, (byte) 0x6e,
//			(byte) 0x20, (byte) 0x50, (byte) 0x69, (byte) 0x6e, (byte) 0x20, (byte) 0x23, (byte) 0x30, (byte) 0x3a };
	public static final byte[] BCD_SIZE_PER_BYTES = { 0, 3, 5, 8, 10, 13, 15, 17, 20, 22, 25, 27, 29, 32, 34, 37, 39,
			41, 44, 46, 49, 51, 53, 56, 58, 61, 63, 66, 68, 70, 73, 75, 78 };
	public static final byte[] TXT_CRED_MENU_LIST = { (byte) 0x0e, (byte) 0x50, (byte) 0x49, (byte) 0x4e, (byte) 0x20,
			(byte) 0x26, (byte) 0x20, (byte) 0x50, (byte) 0x41, (byte) 0x53, (byte) 0x53, (byte) 0x57, (byte) 0x4f,
			(byte) 0x52, (byte) 0x44, (byte) 0x09, (byte) 0x4f, (byte) 0x54, (byte) 0x50, (byte) 0x20, (byte) 0x43,
			(byte) 0x4f, (byte) 0x44, (byte) 0x45, (byte) 0x53, (byte) 0x08, (byte) 0x51, (byte) 0x52, (byte) 0x20,
			(byte) 0x43, (byte) 0x4f, (byte) 0x44, (byte) 0x45, (byte) 0x53, (byte) 0x08, (byte) 0x4e, (byte) 0x4f,
			(byte) 0x54, (byte) 0x45, (byte) 0x42, (byte) 0x4f, (byte) 0x4f, (byte) 0x4b, (byte) 0x09, (byte) 0x4f,
			(byte) 0x52, (byte) 0x47, (byte) 0x41, (byte) 0x4e, (byte) 0x49, (byte) 0x5a, (byte) 0x45, (byte) 0x52 };
	public static final short[] MENU_LIST_TITLE_OFF = {(short) 1, (short) 16, (short) 26, (short) 35, (short) 44};
	public static final short[] MENU_LIST_TITLE_LEN = {(short) 3, (short) 3, (short) 2, (short) 8, (short) 9};

	public APIShim() {
		aocPin = new byte[8];
		generateRandomAOCPin(aocPin, (short) 0, (short) aocPin.length);
	}

	private void generateRandomAOCPin(byte[] pin, short off, short len) {
		ThetaPassApplet.randomData.generateData(nonceBuffer, (short) 0, (short) len);
		for (short i = (short) 0; i < len; i++) {
//			 Use the rightmost 4 nibbles of bytes from random byte and mod 10 to get a
//			 numerical digit and then convert back to its byte form
			pin[(short) (i + off)] = (byte) (((short) ((byte) (nonceBuffer[i] & 0x0F) % (short) 10) & 0xFF) | 0x30);
		}
	}

	public boolean initEnv(byte[] apduBuffer) {
		boolean isProceed = false;
		Util.arrayFillNonAtomic(apduBuffer, (short) 0, (short) 256, (byte) 0x00);
		apduBuffer[0] = T101OpenAPI.CRED_CLASS_PIN;
		Util.arrayCopyNonAtomic(aocPin, (short) 0, apduBuffer, (short) 1, (short) aocPin.length);
		Util.arrayCopyNonAtomic(appName, (short) 0, apduBuffer, (short) (1 + aocPin.length), (short) appName.length);
		Util.arrayCopyNonAtomic(defaultExpiryTime, (short) 0, apduBuffer, (short) (1 + aocPin.length + appName.length),
				(short) 4);
		isProceed = ThetaPassApplet.api.createAOCContainer(apduBuffer[0], apduBuffer, (short) 1, (short) aocPin.length,
				aocPinMaxRetry, apduBuffer, (short) (1 + aocPin.length), (short) appName.length, apduBuffer,
				(short) (1 + aocPin.length + appName.length));

		// Finalize container
		if (isProceed) {
			isProceed = finalizeContainer(aocPin, (short) 0, (short) aocPin.length, apduBuffer);
		}

		// Change front panel administration to enabled
		if (isProceed) {
			isProceed = enableFPAccess(aocPin, (short) 0, (short) aocPin.length, apduBuffer);
		} else {
			ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0xa3));
		}
		return isProceed;
	}

	public boolean enableFPAccess(byte[] aocPin, short aocPinOffset, short aocPinLen, byte[] buffer) {
		buffer[0] = T101OpenAPI.CRED_FIELD_MANAGEMENT;
		buffer[1] = T101OpenAPI.CRED_MGMT_FRONT_PANEL;
		if (ThetaPassApplet.api.manageAOCContainer(buffer[0], buffer, (short) 1, (short) 1, buffer, (short) 2)) {
			Util.arrayCopyNonAtomic(buffer, (short) 2, nonceBuffer, (short) 0, (short) 8);
			if (authContainer(aocPin, aocPinOffset, aocPinLen, nonceBuffer, (short) 0, buffer) == 1) {
				return true;
			} else {
				ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0x17));
			}
		} else {
			ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0x16));
		}
		return false;
	}

	public boolean destroyEnv() {
		return ThetaPassApplet.api.destroyAOCContainer();
	}

	public short authContainer(byte[] secret, short secOffset, short secLen, byte[] nonce, short nonceOffset,
			byte[] apduBuffer) {
		apduBuffer[0] = MessageDigest.ALG_SHA_256;
		Util.arrayCopyNonAtomic(secret, secOffset, apduBuffer, (short) 1, secLen);
		Util.arrayCopyNonAtomic(nonce, nonceOffset, apduBuffer, (short) (1 + secLen), (short) 8);

		ThetaPassApplet.api.cryptoHMAC(apduBuffer[0], // hashType
				apduBuffer, (short) 1, secLen, // key
				apduBuffer, (short) (1 + secLen), (short) 8, // nonce
				apduBuffer, (short) (9 + secLen), // ipad
				apduBuffer, (short) (73 + secLen), // opad
				apduBuffer, (short) (137 + secLen), // secBuff
				apduBuffer, (short) 201); // output

		// Call extendedRequest to submit final signed nonce result
		return ThetaPassApplet.api.extendedRequest(apduBuffer, (short) 201, (short) 32, apduBuffer, (short) 0);
	}

	public boolean finalizeContainer(byte[] aocPin, short aocPinOffset, short aocPinLen, byte[] apduBuffer) {
		if (ThetaPassApplet.api.finalizeNewContainer(apduBuffer, (short) 0)) {
			Util.arrayCopyNonAtomic(apduBuffer, (short) 0, nonceBuffer, (short) 0, (short) 8);
			if (authContainer(aocPin, aocPinOffset, aocPinLen, nonceBuffer, (short) 0, apduBuffer) == 1) {
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

	public void opsCancelStatusUI(byte[] title, short titleOffset, short titleLen, byte[] apduBuffer) {
		uxRender(T101OpenAPI.UI_TYPE_TEXT, T101OpenAPI.NULL, T101OpenAPI.NULL, T101OpenAPI.NULL, T101OpenAPI.NULL,
				title, titleOffset, titleLen, TXT_CANCELLED, (short) 0, (short) TXT_CANCELLED.length, aocPin, (short) 0,
				(short) aocPin.length, apduBuffer);
	}

	public short pinInputUI(byte[] title, short titleOffset, short titleLen, byte[] message, short mOffset, short mLen,
			byte[] apduBuffer) {
		return uxRender(T101OpenAPI.UI_TYPE_INPUT, (byte) 0x01, (byte) 0x01, (byte) 0xFF, (byte) 0x20, title,
				titleOffset, titleLen, message, mOffset, mLen, aocPin, (short) 0, (short) aocPin.length, apduBuffer);
	}

	public short mainMenuUI(byte[] apduBuffer) {
		return uxRender(T101OpenAPI.UI_TYPE_LIST, (byte) 0xFF, (byte) 0x05, T101OpenAPI.NULL, T101OpenAPI.NULL, appName,
				(short) 0, (short) appName.length, TXT_CRED_MENU_LIST, (short) 0, (short) TXT_CRED_MENU_LIST.length,
				aocPin, (short) 0, (short) aocPin.length, apduBuffer);
	}

	public short showMenuKeyQR(byte[] menuKey, byte[] apduBuffer) {
		return uxRender(T101OpenAPI.UI_TYPE_QR, (byte) 0x01, (byte) 0x01, (byte) 0xFF, (byte) 0x20, appName, (short) 0,
				(short) appName.length, menuKey, (short) 1, (short) (menuKey[0] & 0xFF), aocPin, (short) 0,
				(short) aocPin.length, apduBuffer);
	}

	public short showScrollingList(byte[] title, short titleOffset, short titleLen, short itemCount, byte[] input,
			short offset, short len, byte[] apduBuffer) {
		return uxRender(T101OpenAPI.UI_TYPE_LIST, (byte) 0x00, (byte) (itemCount & 0xFF), (byte) 0x00, (byte) 0x00,
				title, titleOffset, titleLen, input, offset, len, aocPin, (short) 0, (short) aocPin.length, apduBuffer);
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

		snonceBuffer = ThetaPassApplet.api.uiSession(apduBuffer[0], subMode, subMode1, subMode2, subMode3, apduBuffer,
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

	public static void shortToBytes(short s, byte[] b, short offset) {
		b[offset] = (byte) ((s >> 8) & 0xFF);
		b[(short) (offset + 1)] = (byte) (s & 0xFF);
	}

	public static short toDecimalASCII(byte[] uBigBuf, short uBigOff, short uBigLen, byte[] decBuf, short decOff) {
		short bcdDigits = (short) BCD_SIZE_PER_BYTES[uBigLen];
		short byteValue, dividend, remainder;

		for (short bcdIndex = 0; bcdIndex < bcdDigits; bcdIndex++) {
			remainder = 0;
			for (short uBigIndex = 0; uBigIndex < uBigLen; uBigIndex++) {
				byteValue = (short) (uBigBuf[(short) (uBigOff + uBigIndex)] & 0xFF);
				dividend = (short) (remainder * 256 + byteValue);
				remainder = (short) (dividend % 10);
				uBigBuf[(short) (uBigOff + uBigIndex)] = (byte) (dividend / 10);
			}
			decBuf[(short) (decOff + bcdDigits - bcdIndex - 1)] = (byte) (remainder + '0');
		}

		return bcdDigits;
	}
}
