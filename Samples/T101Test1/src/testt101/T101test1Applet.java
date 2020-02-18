package testt101;

import KM101.T101OpenAPI;
import javacard.framework.*;
import javacard.security.MessageDigest;
import javacardx.annotations.*;

/**
 * Applet class
 * 
 * @author ThothTrust Pte Ltd.
 */
@StringPool(value = { @StringDef(name = "Package", value = "testt101"),
		@StringDef(name = "AppletName", value = "T101test1Applet") },
		// Insert your strings here
		name = "T101test1AppletStrings")
public class T101test1Applet extends Applet implements AppletEvent {

	public AID apiAID;
	public T101OpenAPI api = null;
	public static byte[] serverAID = new byte[] { (byte) 0x4B, (byte) 0x4D, (byte) 0x31, (byte) 0x30, (byte) 0x31,
			(byte) 0x00 };
	public short[] sb = JCSystem.makeTransientShortArray((short) 3, JCSystem.CLEAR_ON_RESET);
	public byte[] TEXT_SETUP_COMPLETE = new byte[] { (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20,
			(byte) 0x53, (byte) 0x65, (byte) 0x74, (byte) 0x75, (byte) 0x70, (byte) 0x20, (byte) 0x20, (byte) 0x20,
			(byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x43,
			(byte) 0x6f, (byte) 0x6d, (byte) 0x70, (byte) 0x6c, (byte) 0x65, (byte) 0x74, (byte) 0x65, (byte) 0x20,
			(byte) 0x20, (byte) 0x20, (byte) 0x20 };

	public byte[] TEXT_FAILED = new byte[] { (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x4f, (byte) 0x70,
			(byte) 0x65, (byte) 0x72, (byte) 0x61, (byte) 0x74, (byte) 0x69, (byte) 0x6f, (byte) 0x6e, (byte) 0x20,
			(byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x46,
			(byte) 0x61, (byte) 0x69, (byte) 0x6c, (byte) 0x65, (byte) 0x64, (byte) 0x20, (byte) 0x20, (byte) 0x20,
			(byte) 0x20, (byte) 0x20 };
	public static byte[] b0;
	public byte[] aocPin = null;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new T101test1Applet();
	}

	protected T101test1Applet() {
		b0 = JCSystem.makeTransientByteArray((short) 258, JCSystem.CLEAR_ON_RESET);
		register();
	}

	public void uninstall() {
		destroyEnv();
	}

	@Override
	public void process(APDU apdu) {
		if (selectingApplet()) {
			return;
		}

		byte[] buffer = apdu.getBuffer();
		if ((buffer[ISO7816.OFFSET_CLA] == (byte) 0xB0) && (buffer[ISO7816.OFFSET_INS] == (byte) 0x00)) {
			if (api == null) {
				try {
					apiAID = JCSystem.lookupAID(serverAID, (short) 0, (byte) serverAID.length);
				} catch (Exception e) {
					ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
				}
				if (apiAID != null) {
					api = (T101OpenAPI) JCSystem.getAppletShareableInterfaceObject(apiAID, (byte) 0);
					if (api == null) {
						ISOException.throwIt(ISO7816.SW_APPLET_SELECT_FAILED);
					}
				} else {
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				}
			}
		} else if ((buffer[ISO7816.OFFSET_CLA] == (byte) 0xB0) && (buffer[ISO7816.OFFSET_INS] == (byte) 0x01)) {
			/**
			 * Accept in APDU format: <aocPinLen - 1><appNameLen - 1><adminUserLen -
			 * 1><adminUserPinLen - 1><expiryTime - 4><aocPin - aocPinLen><appName -
			 * appNameLen><adminUser - adminUserLen><adminUserPin - adminUserPinLen>
			 */
			sb[0] = apdu.setIncomingAndReceive();
			if (sb[0] < 8) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			} else {
				// Read aocPinLen
				short aocPinLen = (short) (buffer[5] & 0xFF);
				// Read appNameLen
				short appNameLen = (short) (buffer[6] & 0xFF);
				// Read adminUserLen
				short adminUserLen = (short) (buffer[7] & 0xFF);
				// Read adminUserPinLen
				short adminUserPinLen = (short) (buffer[8] & 0xFF);
				// Hard-coded PIN retry
				short pinRetry = (short) 5;

				if (aocPinLen == 0 || appNameLen == 0 || adminUserLen == 0 || adminUserPinLen == 0) {
					ISOException.throwIt(ISO7816.SW_DATA_INVALID);
				} else {
					// Create aocPin byte array and store it.
					aocPin = new byte[aocPinLen];
					Util.arrayCopyNonAtomic(buffer, (short) 13, aocPin, (short) 0, aocPinLen);

					// Buffer off expiry timestamp to starting of b0 buffer (assumed 4 bytes of hex)
					Util.arrayCopyNonAtomic(buffer, (short) 9, b0, (short) 0, (short) 4);

					// Copy appName to b0 buffer
					Util.arrayCopyNonAtomic(buffer, (short) (13 + aocPinLen), b0, (short) 4, appNameLen);

					// Copy adminUser to b0 buffer
					Util.arrayCopyNonAtomic(buffer, (short) (13 + aocPinLen + appNameLen), b0, (short) (4 + appNameLen),
							adminUserLen);

					// Copy adminUserPin to b0 buffer
					Util.arrayCopyNonAtomic(buffer, (short) (13 + aocPinLen + appNameLen + adminUserLen), b0,
							(short) (4 + appNameLen + adminUserLen), adminUserPinLen);

					// Execute initEnv() function
					initEnv(aocPin, (short) 0, (short) aocPin.length, b0, (short) 4, appNameLen, b0,
							(short) (4 + appNameLen), adminUserLen, b0, (short) (4 + appNameLen + adminUserLen),
							adminUserPinLen, b0, (short) 0, pinRetry, buffer);
				}
			}
		} else {
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	public boolean destroyEnv() {
		if (api != null) {
			api.destroyAOCContainer();
			return true;
		}

		return false;
	}

	public void initEnv(byte[] aocPin, short aocPinOffset, short aocPinLen, byte[] appName, short appNameOffset,
			short appNameLen, byte[] adminUser, short adminUserOffset, short adminUserLen, byte[] adminPin,
			short adminPinOffset, short adminPinLen, byte[] expiryTime, short expiryOffset, short authTries,
			byte[] buffer) {
		boolean isProceed = false;
		if (api != null) {
			sb[0] = (short) (6 + aocPinLen + appNameLen);
			Util.arrayFillNonAtomic(buffer, (short) 0, (short) 256, (byte) 0x00);
			buffer[0] = api.CRED_CLASS_PIN;
			Util.arrayCopyNonAtomic(aocPin, aocPinOffset, buffer, (short) 1, (short) aocPinLen);
			Util.arrayCopyNonAtomic(appName, appNameOffset, buffer, (short) (1 + aocPinLen), appNameLen);
			Util.arrayCopyNonAtomic(expiryTime, expiryOffset, buffer, (short) (1 + aocPinLen + appNameLen), (short) 4);
			isProceed = api.createAOCContainer(buffer[0], buffer, (short) 1, (short) aocPinLen, authTries, buffer,
					(short) (1 + aocPinLen), (short) appNameLen, buffer,
					(short) (1 + aocPinLen + appNameLen));

			if (!isProceed) {
				ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0x2F));
			}

			// Enroll Admin
			if (isProceed) {
				try {

					isProceed = enrollNewAdminUsers(adminUser, adminUserOffset, adminUserLen, adminPin, adminPinOffset,
							adminPinLen, expiryTime, expiryOffset, aocPin, aocPinOffset, aocPinLen, buffer);
				} catch (Exception e) {
					ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0xf2));
				}
			} else {
				ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0xa1));
			}

			// Finalize container
			if (isProceed) {
				try {
					isProceed = finalizeContainer(aocPin, aocPinOffset, aocPinLen, buffer);
				} catch (Exception e) {
					ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0xf3));
				}
			} else {
				ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0xa2));

			}

			if (isProceed) {
				uxRender(T101OpenAPI.UI_TYPE_TEXT, T101OpenAPI.NULL, T101OpenAPI.NULL, T101OpenAPI.NULL,
						T101OpenAPI.NULL, TEXT_SETUP_COMPLETE, (short) 5, (short) 5, TEXT_SETUP_COMPLETE, (short) 0,
						(short) TEXT_SETUP_COMPLETE.length, aocPin, aocPinOffset, aocPinLen, buffer);
			} else {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
		}
	}

	public short authContainer(byte[] secret, short secOffset, short secLen, byte[] nonce, short nonceOffset,
			byte[] buffer) {
		buffer[0] = MessageDigest.ALG_SHA_256;
		Util.arrayCopyNonAtomic(secret, secOffset, buffer, (short) 1, secLen);
		Util.arrayCopyNonAtomic(nonce, nonceOffset, buffer, (short) (1 + secLen), (short) 8);

		api.cryptoHMAC(buffer[0], // hashType
				buffer, (short) 1, secLen, // key
				buffer, (short) (1 + secLen), (short) 8, // nonce
				buffer, (short) (9 + secLen), // ipad
				buffer, (short) (73 + secLen), // opad
				buffer, (short) (137 + secLen), // secBuff
				buffer, (short) 201); // output

		// Call extendedRequest to submit final signed nonce result
		sb[0] = api.extendedRequest(buffer, (short) 201, (short) 32, buffer, (short) 0);
		return sb[0];
	}

	public boolean finalizeContainer(byte[] aocPin, short aocPinOffset, short aocPinLen, byte[] buffer) {
		if (api.finalizeNewContainer(buffer, (short) 0)) {
			Util.arrayCopyNonAtomic(buffer, (short) 0, b0, (short) 0, (short) 8);
			if (authContainer(aocPin, aocPinOffset, aocPinLen, b0, (short) 0, buffer) == 1) {
				return true;
			}
		}

		return false;
	}

	public boolean enrollNewAdminUsers(byte[] adminUser, short adminUserOffset, short adminUserLen, byte[] adminPin,
			short adminPinOffset, short adminPinLen, byte[] expiryTime, short expiryTimeOffset, byte[] aocPin,
			short aocPinOffset, short aocPinLen, byte[] buffer) {
		buffer[0] = T101OpenAPI.CRED_CLASS_PIN;
		buffer[1] = T101OpenAPI.CRED_MGMT_FRONT_PANEL;
		Util.arrayCopyNonAtomic(adminPin, adminPinOffset, buffer, (short) 2, adminPinLen);
		Util.arrayCopyNonAtomic(adminUser, adminUserOffset, buffer, (short) (2 + adminPinLen), adminUserLen);
		Util.arrayCopyNonAtomic(expiryTime, expiryTimeOffset, buffer, (short) (2 + adminPinLen + adminUserLen),
				(short) 4);
		if (api.newAOCUserCred(buffer[0], buffer, (short) 2, (short) adminPinLen, (short) 3, buffer,
				(short) (2 + adminPinLen), (short) adminUserLen, buffer, (short) (2 + adminPinLen + adminUserLen),
				T101OpenAPI.NULL, null, (short) 0, (short) 0, T101OpenAPI.AUTH_INTERNAL, buffer,
				(short) (6 + adminPinLen + adminUserLen))) {
			if (authContainer(aocPin, aocPinOffset, aocPinLen, buffer, (short) (6 + adminPinLen + adminUserLen),
					buffer) == 1) {
				return true;
			} else {
				ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0x15));
			}
		} else {
			ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0x14));
		}

		return false;
	}

	public short uxRender(byte type, byte subMode, byte subMode1, byte subMode2, byte subMode3, byte[] title,
			short titleOffset, short titleLen, byte[] input, short inOffset, short inLen, byte[] aocPin,
			short aocPinOffset, short aocPinLen, byte[] buffer) {
		buffer[0] = type;
		sb[1] = (short) 0;
		sb[2] = (short) 0;
		if (title != null && titleLen > 0) {
			Util.arrayCopyNonAtomic(title, titleOffset, buffer, (short) 1, titleLen);
			sb[1] = titleLen;
		}

		if (input != null && inLen > 0) {
			Util.arrayCopyNonAtomic(input, inOffset, buffer, (short) (1 + sb[1]), inLen);
			sb[2] = inLen;
		}

		sb[0] = api.uiSession(buffer[0], subMode, subMode1, subMode2, subMode3, buffer, (short) 1, sb[1], buffer,
				(short) (1 + sb[1]), sb[2], buffer, (short) (1 + sb[1] + sb[2]));
		if (sb[0] != -1) {
			Util.arrayCopyNonAtomic(buffer, (short) (1 + sb[1] + sb[2]), b0, (short) 0, (short) 8);
			sb[0] = authContainer(aocPin, aocPinOffset, aocPinLen, b0, (short) 0, buffer);
			if (sb[0] > -1) {
				return sb[0];
			} else {
				ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0xc2));
			}
		} else {
			ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0xc1));
		}
		return (short) -1;
	}
}
