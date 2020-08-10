package thetapass;

import KM101.T101OpenAPI;
import javacard.framework.*;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

/**
 * Applet class
 * 
 * @author ThothTrust Pte Ltd.
 */
public class ThetaPassApplet extends Applet implements AppletEvent {

	public static final short APP_VERSION = (byte) 0x0100;
	public static final short PROTO_VERSION = (byte) 0x0100;

	public static final byte CLA = (byte) 0xB0;
	public static final byte INS_MAIN_MENU = (byte) 0x10;
	public static final byte INS_OPEN_SCHANNEL = (byte) 0x50;
	public static final byte INS_AUTHENTICATE = (byte) 0x82;
	public static final byte INS_UPDATE_AUTH = (byte) 0x83;
	public static final byte INS_GET_RECORD = (byte) 0xCA;
	public static final byte INS_PUT_RECORD = (byte) 0xDA;
	public static final byte INS_DELETE_RECORD = (byte) 0xEA;

	public static final short FS_TOTAL_RECORDS = 64;
	public static final short FS_OFF_FLAG_SETTING = 0;
	public static final short FS_OFF_FLAG_ENAME0_LEN = 1;
	public static final short FS_OFF_FLAG_ENAME1_LEN = 2;
	public static final short FS_OFF_FLAG_CONTENT_LEN = 3;
	public static final short FS_OFF_ENAME0 = 4;
	public static final short FS_OFF_ENAME1 = 19;
	public static final short FS_OFF_CONTENT = 67;
	public static final short FS_MAX_ENAME0_LEN = 15;
	public static final short FS_MAX_ENAME1_LEN = 48;
	public static final short FS_MAX_CONTENT = 80;
	public static final short FS_MAX_RECORD = FS_MAX_ENAME0_LEN + FS_MAX_ENAME1_LEN + FS_MAX_CONTENT + 4;
	public static final byte FS_FLAG_ISACTIVE = (byte) 0x80;
	public static final byte FS_FLAG_REQUIRE_AUTH = (byte) 0x40;
	public static final byte FS_FLAG_HIDE_UNLESS_AUTH = (byte) 0x20;
	public static final byte FS_FLAG_TYPE_OTP = (byte) 0x01;
	public static final byte FS_FLAG_TYPE_PWD = (byte) 0x02;
	public static final byte FS_FLAG_TYPE_QR = (byte) 0x03;
	public static final byte FS_FLAG_TYPE_TXT = (byte) 0x04;
	public static final byte FS_FLAG_TYPE_ORGANIZER = (byte) 0x05;
	public static final byte FS_FLAG_TYPE_FIDO = (byte) 0x06;

	public static final short PIN_DEFAULT_RETRY = 5;
	public static final short PIN_DEFAULT_MAX_LEN = 32;
	public static final short PIN_DEFAULT_MIN_LEN = 4;

	public static final short SW_CARD_NOT_READY = 0x6f1f;
	public static final short SW_SCHANNEL_REQ_INIT = 0x6fcc;
	public static final short SW_SCHANNEL_ERROR = 0x6fcd;
	public static final short SW_FS_ERROR = 0x6f31;
	public static final short SW_UI_ERROR = 0x6f51;

	public static RandomData randomData = null;
	private Cipher cipher = null;
	private Cipher cipherNoPad = null;
	private KeyAgreement ecdh = null;
	private MessageDigest md = null;
	public static T101OpenAPI api = null;
	public static APIShim apishim = null;
	public AID apiAID = null;
	public static byte[] serverAID = new byte[] { (byte) 0x4B, (byte) 0x4D, (byte) 0x31, (byte) 0x30, (byte) 0x31,
			(byte) 0x00 };
	private byte[] defaultPin = new byte[] { (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34 };

	private byte[] fs;
	private byte[] fsIV;
	private AESKey fsKey;
	private AESKey sessKey = null;
	private OwnerPIN pin;
	private KeyPair kp;
	private ECPrivateKey privKey;
	private ECPublicKey pubKey;

	private byte[] b0 = JCSystem.makeTransientByteArray((short) 240, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
	private byte[] b1 = JCSystem.makeTransientByteArray((short) 4, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
	private byte[] b2 = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_RESET);
	private short[] sb = JCSystem.makeTransientShortArray((short) 3, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);

	/**
	 * Installs this applet.
	 * 
	 * @param bArray  the array containing installation parameters
	 * @param bOffset the starting offset in bArray
	 * @param bLength the length in bytes of the parameter data in bArray
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new ThetaPassApplet();
	}

	/**
	 * Only this class's install method should create the applet object.
	 */
	protected ThetaPassApplet() {
		fs = new byte[FS_TOTAL_RECORDS * FS_MAX_RECORD];
		fsIV = new byte[(short) 16];
		randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		cipher = Cipher.getInstance(Cipher.ALG_AES_CBC_PKCS5, false);
		cipherNoPad = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
		pin = new OwnerPIN((byte) (PIN_DEFAULT_RETRY & 0xFF), (byte) (PIN_DEFAULT_MAX_LEN & 0xFF));
		pin.update(defaultPin, (short) 0, (byte) (defaultPin.length & 0xFF));
		fsKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
		sessKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_256, false);
		randomData.generateData(b0, (short) 0, (short) 32);
		fsKey.setKey(b0, (short) 0);
		randomData.generateData(fsIV, (short) 0, (short) 16);
		Util.arrayFillNonAtomic(b0, (short) 0, (short) b0.length, (byte) 0x00);
		privKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
		pubKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
		ECC.setCurveParameters(privKey);
		ECC.setCurveParameters(pubKey);
		kp = new KeyPair(pubKey, privKey);
		kp.genKeyPair();
		ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
		register();
	}

	public void uninstall() {
		api.destroyAOCContainer();
	}

	private final void initAPI(byte[] apdubuf) {
		if (api == null) {
			try {
				apiAID = JCSystem.lookupAID(serverAID, (short) 0, (byte) serverAID.length);
			} catch (Exception e) {
				ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			}
			if (apiAID != null) {
				try {
					api = (T101OpenAPI) JCSystem.getAppletShareableInterfaceObject(apiAID, (byte) 0);
				} catch (Exception e) {
					ISOException.throwIt(ISO7816.SW_APPLET_SELECT_FAILED);
				}
				if (api == null) {
					ISOException.throwIt(ISO7816.SW_APPLET_SELECT_FAILED);
				}
				apishim = new APIShim();
				api.destroyAOCContainer();
				if (!apishim.initEnv(apdubuf)) {
					ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
				}
			} else {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
		}
	}

	/**
	 * Demo Menu =========
	 * 
	 * <code>
	 * +-+--------------+
	 * |1|  THETAPASS   |
	 * +-+--------------+
	 * |> PIN & PASSWORD|
	 * |  OTP CODES     |
	 * |  QR CODES      |
	 * |  NOTEBOOK      |
	 * |  ORGANIZER     |
	 * |                |
	 * +----------------+
	 * </code>
	 */
	private void mainMenu(APDU apdu, byte[] buffer) {
		// Buffer b0 memory layout
		// 0 .. 63 = Record position layout
		// 64 .. 160 = List data layout
		short option = -1;
		short itmCnt = 0;
		short itmPtr = 0;
		short itmSelect = 0;
		short listSize = 0;
		short listPtr = 64;
		short dataBytes = 0;
		boolean loop = false;

		option = apishim.mainMenuUI(buffer);
		if (option != 2) {
			ISOException.throwIt(SW_UI_ERROR);
		}

		if (buffer[0] == (byte) 0x01) {

			option = (short) (buffer[1] & 0xFF);

			if (option == 0) {
				// Pin & Password option
				// Get total PWD type objects
				itmCnt = listRecordLocIndexWithType(FS_FLAG_TYPE_PWD, b0, (short) 0);
			} else if (option == 1) {
				// OTP Codes option
				itmCnt = listRecordLocIndexWithType(FS_FLAG_TYPE_OTP, b0, (short) 0);
			} else if (option == 2) {
				// QR Codes option
				itmCnt = listRecordLocIndexWithType(FS_FLAG_TYPE_QR, b0, (short) 0);
			} else if (option == 3) {
				// Notebook option
				itmCnt = listRecordLocIndexWithType(FS_FLAG_TYPE_TXT, b0, (short) 0);
			} else if (option == 4) {
				// Organizer option
				itmCnt = listRecordLocIndexWithType(FS_FLAG_TYPE_ORGANIZER, b0, (short) 0);
			}

			if (itmCnt > 0) {
				loop = true;
			}

			while (loop) {
				// Continue loading more items to viewing list if current list item size is less
				// than 6 items and the item pointer is less than the total item
				while ((listSize < 6) && (itmPtr <= (itmCnt - 1))) {
					// Load item onto viewing list via ENAME0
					b0[listPtr] = (byte) (getEName0FromLocOff(getRecordLocOffset(b0[itmPtr]), b0, (short) (listPtr + 1))
							& 0xFF);

					// Increment listPtr
					listPtr += (short) ((b0[listPtr] & 0xFF) + 1);

					// Increment list size
					listSize++;

					// Increment itmPtr
					itmPtr++;
				}

				// Display viewing list and listen for user input
				if (apishim.showScrollingList(apishim.TXT_CRED_MENU_LIST, apishim.MENU_LIST_TITLE_OFF[option],
						apishim.MENU_LIST_TITLE_LEN[option], listSize, b0, (short) 64, (short) (listPtr - 64),
						buffer) != 2) {
					ISOException.throwIt(SW_UI_ERROR);
				}

				// When displaying item, show ENAME1 and then continue to show Content
				if (buffer[0] == (byte) 0x01) {
					// Input is OK, display selected item's ENAME1
					// Debug, hard-code target item 0 (first password item)
					itmSelect = (short) (itmPtr - listSize + (short) (buffer[1] & 0xFF));
//					ISOException.throwIt(Util.makeShort((byte) 0x6f, b0[itmSelect]));
					dataBytes = getEName1FromLocOff(getRecordLocOffset(b0[itmSelect]), b0, (short) 160);

					if (apishim.confirmationUI(apishim.TXT_CRED_MENU_LIST, apishim.MENU_LIST_TITLE_OFF[option],
							apishim.MENU_LIST_TITLE_LEN[option], b0, (short) 160, dataBytes, buffer)) {
						// Proceed to show CONTENT because user presses OK
						dataBytes = (short) (fs[(short) (getRecordLocOffset(b0[itmSelect]) + FS_OFF_FLAG_CONTENT_LEN)]
								& 0xFF);

						// Decrypt secret CONTENT data
						if (!cryptoContent(Cipher.MODE_DECRYPT, b0[itmSelect], b0, (short) 160, buffer, (short) 0))
							ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

						// Show decrypted secret CONTENT data
						apishim.confirmationUI(apishim.TXT_CRED_MENU_LIST, apishim.MENU_LIST_TITLE_OFF[option],
								apishim.MENU_LIST_TITLE_LEN[option], b0, (short) 160, dataBytes, buffer);
						
						// Go back to current page
						if (itmPtr <= 6) {
							itmPtr = 0;
						} else {
							itmPtr -= (short) (listSize + 6);
						}						
					}
				} else if (buffer[0] == (byte) 0x02) {
					// Input is C, quit from the loop
					break;
				} else if (buffer[0] == (byte) 0x03) {
					// Down arrow is ignored as itmPtr is already poised for next items
					if (buffer[1] == (byte) 0xFE) {
						// Input is Up arrow pressed at first item, move list items to previous 6 items
						if ((short) (itmPtr - listSize - 6) <= (short) (itmCnt - 1)) {
							if (itmPtr <= 6) {
								itmPtr = 0;
							} else {
								itmPtr -= (short) (listSize + 6);
							}
						}
					}
				}

				// Reset list size and pointer to prepare for next round of items to be loaded
				listSize = 0;
				listPtr = 64;
			}

//			// Debug
//			apdu.setOutgoing();
//			apdu.setOutgoingLength((short) (listPtr - 64));
//			apdu.sendBytesLong(b0, (short) 64, (short) (listPtr - 64));
		}

		return;

	}

	/**
	 * Establishes secure channel before any external operation can proceed.
	 * 
	 * @param apdu
	 * @param apduBuf
	 */
	private void secureChannel(APDU apdu, byte[] apduBuf) {
		// ECDH based SChannel establishment with static-ephermeral construct.
		sb[0] = apdu.setIncomingAndReceive();

		if (sb[0] == (short) 65) {
			// Reset buffers
			Util.arrayFillNonAtomic(b0, (short) 0, (short) b0.length, (byte) 0x00);
			Util.arrayFillNonAtomic(b2, (short) 0, (short) b2.length, (byte) 0x00);

			// Create IV by concatenating client public key || card public key, sha256 hash
			// and extract first 12 bytes
			md.reset();
			md.update(apduBuf, (short) 5, (short) 65);
			pubKey.getW(b0, (short) 0);
			md.doFinal(b0, (short) 0, (short) 65, b0, (short) 65);
			Util.arrayCopyNonAtomic(b0, (short) 65, b2, (short) 0, (short) 12);

			// ECDH
			ecdh.init(privKey);
			try {
				ecdh.generateSecret(apduBuf, (short) 5, (short) 65, b0, (short) 0);
			} catch (Exception e) {
				ISOException.throwIt(SW_SCHANNEL_ERROR);
			}

			// Hash shared secret with SHA-256
			md.reset();
			md.doFinal(b0, (short) 0, (short) 32, b0, (short) 0);

			// Set as session key
			sessKey.setKey(b0, (short) 0);

			// Hash a second time to generate a one-time confirmation code
			md.reset();
			md.doFinal(b0, (short) 0, (short) 32, b0, (short) 0);

			// Generate on screen a one-time confirmation code
			short offset = (short) (b0[(short) 31] & 0xf);

			int binary = ((b0[(short) (offset)] & 0x7f) << 24) | ((b0[(short) (offset + 1)] & 0xff) << 16)
					| ((b0[(short) (offset + 2)] & 0xff) << 8) | (b0[(short) (offset + 3)] & 0xff);

			// 6 digit OTP code modulus math
			Codec.intToBytes(binary % 1000000, b0, (short) 0);

			// Convert back to bytes
			sb[0] = Codec.toDecimalASCII(b0, (short) 0, (short) 4, apduBuf, (short) 0);
			Util.arrayCopyNonAtomic(apduBuf, (short) 4, b0, (short) 96, (short) 6);

			// Fill whitespaces before creating confirmation message
			Util.arrayFillNonAtomic(b0, (short) 0, (short) 96, (byte) 0x20);

			// OTP Code
			Util.arrayCopyNonAtomic(APIShim.TXT_CCODE, (short) 0, b0, (short) 0, (short) APIShim.TXT_CCODE.length);
			// :
			b0[(short) APIShim.TXT_CCODE.length] = (byte) 0x3A;

			// Set session password
			Util.arrayCopyNonAtomic(b0, (short) 96, b0, (short) 16, (short) 6);

			// Set prompt OK/C press
			Util.arrayCopyNonAtomic(APIShim.TXT_PROMPT_OKC, (short) 0, b0, (short) 80,
					(short) APIShim.TXT_PROMPT_OKC.length);

			// Format and send GUI session request
			apishim.confirmationUI(APIShim.TXT_SECURE_SESS, (short) 0, (short) APIShim.TXT_SECURE_SESS.length, b0,
					(short) 0, (short) 96, apduBuf);

		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
	}

	// Input buffer must not be the same as apiBuffer to prevent data access
	// collisions. The apiBuffer serves as output as well.
	private short securePacketProcess(byte mode, byte[] params, short pOff, short pLen, byte[] input, short inOff,
			short inLen, short sbuff, byte[] apiBuffer) {
		if (sessKey.isInitialized() && (Util.makeShort(b2[12], b2[13]) < 65535)
				&& (Util.makeShort(b2[14], b2[15]) < 65535)) {
			if (mode == Cipher.MODE_ENCRYPT && inLen <= (short) 200) {
				// Derive packet nonce as IV by SHA256 hashing the concatenation of
				// <ClientNonce><ClientCtr><DeviceCtr>
				md.reset();
				md.doFinal(b2, (short) 0, (short) b2.length, apiBuffer, (short) 0);

				// Encrypt data without including IV into ciphertext output
				cipher.init(sessKey, mode, apiBuffer, (short) 0, (short) 16);
				sbuff = cipher.doFinal(input, inOff, inLen, apiBuffer, (short) 16);

				// Compute HMAC-SHA256 using SHA256(<IV><Ciphertext>) with 16 initial bytes of
				// the hash result
				// Generate SHA256 hash for MACing

				// apiBuffer :: <params><iv - 16><ciphertext - sbuff><hash - 32>
				md.reset();
				md.update(params, pOff, pLen);
				md.doFinal(apiBuffer, (short) 0, (short) (16 + sbuff), apiBuffer, (short) (16 + sbuff));

				// Move apiBuffer ciphertext and hash data to KM's internal buffer while
				// omitting iv as it is not needed anymore
				// kmIBuff :: <ciphertext - sbuff><hash - 32>
				Util.arrayCopyNonAtomic(apiBuffer, (short) 16, b0, (short) 0, (short) (32 + sbuff));

				// Get key
				sessKey.getKey(apiBuffer, (short) 0);

				// Copy hash from KM's internal buffer to start of apiBuffer
				// apiBuffer :: <sessKey> - 32<hash - 32>
				Util.arrayCopyNonAtomic(b0, sbuff, apiBuffer, (short) 32, (short) 32);
				api.cryptoHMAC(MessageDigest.ALG_SHA_256, apiBuffer, (short) 0, (short) 32, apiBuffer, (short) 32,
						(short) 32, apiBuffer, (short) 64, apiBuffer, (short) 128, apiBuffer, (short) 192, apiBuffer,
						(short) 0);

				// Copy mac to KM's internal buffer to replace hash
				// kmIBuff :: <ciphertext - sbuff><mac - 32>
				Util.arrayCopyNonAtomic(apiBuffer, (short) 0, b0, sbuff, (short) 32);

				// Copy both ciphertext and mac to apiBuffer from kmIBuff
				// apiBuffer :: <ciphertext - sbuff><mac - 32>
				Util.arrayCopyNonAtomic(b0, (short) 0, apiBuffer, (short) 0, (short) (32 + sbuff));

				// Update device counter
				Codec.shortToBytes((short) (Util.makeShort(b2[14], b2[15]) + 1), b2, (short) 14);

				return (short) (sbuff + 32);
			} else if (mode == Cipher.MODE_DECRYPT && inLen <= (short) 240) {
				// Derive packet nonce as IV by SHA256 hashing the concatenation of
				// <ClientNonce><ClientCtr><DeviceCtr>
				md.reset();
				md.doFinal(b2, (short) 0, (short) b2.length, apiBuffer, (short) 0);

				// Compute HMAC-SHA256 using SHA256(<params><IV><Ciphertext>) with 16 initial
				// bytes of
				// the hash result
				md.reset();
				md.update(params, pOff, pLen);
				md.update(apiBuffer, (short) 0, (short) 16);
				md.doFinal(input, inOff, (short) (inLen - 32), apiBuffer, (short) 32);
				sessKey.getKey(apiBuffer, (short) 0);
				api.cryptoHMAC(MessageDigest.ALG_SHA_256, apiBuffer, (short) 0, (short) 32, apiBuffer, (short) 32,
						(short) 32, apiBuffer, (short) 64, apiBuffer, (short) 128, apiBuffer, (short) 192, apiBuffer,
						(short) 192);
				if (Util.arrayCompare(input, (short) (inLen - 32), apiBuffer, (short) 192, (short) 32) == (byte) 0x00) {
					// Derive packet nonce as IV by SHA256 hashing the concatenation of
					// <ClientNonce><ClientCtr><DeviceCtr> again
					md.reset();
					md.doFinal(b2, (short) 0, (short) b2.length, apiBuffer, (short) 0);

					// Decrypt packet
					cipher.init(sessKey, mode, apiBuffer, (short) 0, (short) 16);
					sbuff = cipher.doFinal(input, inOff, (short) (inLen - 32), apiBuffer, (short) 0);

					// Update client counter
					Codec.shortToBytes((short) (Util.makeShort(b2[12], b2[13]) + 1), b2, (short) 12);
					return sbuff;
				} else {
					// Exit function via exception
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				}
			}
		} else {
			ISOException.throwIt(SW_SCHANNEL_REQ_INIT);
		}
		return (short) -1;
	}

	private void fsGet(APDU apdu, byte[] apduBuf) {
		if (apduBuf[ISO7816.OFFSET_P1] == (byte) 0x00 && apduBuf[ISO7816.OFFSET_P2] == (byte) 0x00) {
			Util.setShort(apduBuf, (short) 0, countFreeRecords());
			Util.setShort(apduBuf, (short) 2, countTotalRecords());
			apdu.setOutgoingAndSend((short) 0, (short) 4);
		} else if (apduBuf[ISO7816.OFFSET_P1] == FS_FLAG_TYPE_OTP || apduBuf[ISO7816.OFFSET_P1] == FS_FLAG_TYPE_PWD
				|| apduBuf[ISO7816.OFFSET_P1] == FS_FLAG_TYPE_QR || apduBuf[ISO7816.OFFSET_P1] == FS_FLAG_TYPE_TXT
				|| apduBuf[ISO7816.OFFSET_P1] == FS_FLAG_TYPE_ORGANIZER
				|| apduBuf[ISO7816.OFFSET_P1] == FS_FLAG_TYPE_FIDO) {
			if (apduBuf[ISO7816.OFFSET_P2] == (byte) 0x00) {
				// Count records by type
				Util.setShort(apduBuf, (short) 0, countRecordByType(apduBuf[ISO7816.OFFSET_P1]));
				apdu.setOutgoingAndSend((short) 0, (short) 2);
			} else if (apduBuf[ISO7816.OFFSET_P2] == (byte) 0x01) {
				sb[0] = apdu.setIncomingAndReceive();
				if (sb[0] != 4) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				// Get offIndex parameter
				short offIndex = Util.makeShort(apduBuf[5], apduBuf[6]);

				// Get recordCount parameter
				short recordCount = Util.makeShort(apduBuf[7], apduBuf[8]);

				if (offIndex > 64 || recordCount > 6) {
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				}

				// Get list from range
				short contentLen = getRecordEName0List(apduBuf[ISO7816.OFFSET_P1], offIndex, recordCount, apduBuf,
						(short) 0);
				if (contentLen == -1)
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				apdu.setOutgoingAndSend((short) 0, contentLen);
			} else if (apduBuf[ISO7816.OFFSET_P2] == (byte) 0x02) {
				// Get specific record content by type and ename0
				sb[0] = apdu.setIncomingAndReceive();
				short recLoc = -1;
				recLoc = searchRecordLocWithEName0AndType(apduBuf[ISO7816.OFFSET_P1], apduBuf, apdu.getOffsetCdata(),
						sb[0]);
				if (recLoc == -1)
					ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
				sb[0] = (short) (fs[(short) (getRecordLocOffset(recLoc) + FS_OFF_FLAG_CONTENT_LEN)] & 0xFF);
				if (!cryptoContent(Cipher.MODE_DECRYPT, recLoc, apduBuf, (short) 0, b0, (short) 0))
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				apdu.setOutgoingAndSend((short) 0, sb[0]);
			} else if (apduBuf[ISO7816.OFFSET_P2] == (byte) 0x03) {
				// Get specific record ename1 by type and ename0
				sb[0] = apdu.setIncomingAndReceive();
				short recLoc = searchRecordLocWithEName0AndType(apduBuf[ISO7816.OFFSET_P1], apduBuf,
						apdu.getOffsetCdata(), sb[0]);
				if (recLoc == -1)
					ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
				sb[0] = getEName1FromLocOff(getRecordLocOffset(recLoc), apduBuf, (short) 0);
				apdu.setOutgoingAndSend((short) 0, sb[0]);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
	}

	private void fsPut(APDU apdu, byte[] apduBuf) {
		sb[0] = apdu.setIncomingAndReceive();
		byte fsType = apduBuf[ISO7816.OFFSET_P1];
		if (fsType == FS_FLAG_TYPE_OTP || apduBuf[ISO7816.OFFSET_P1] == FS_FLAG_TYPE_PWD || fsType == FS_FLAG_TYPE_QR
				|| fsType == FS_FLAG_TYPE_TXT || fsType == FS_FLAG_TYPE_ORGANIZER || fsType == FS_FLAG_TYPE_FIDO) {
			short e0Len = (short) (apduBuf[5] & 0xFF);
			short e1Len = (short) (apduBuf[6] & 0xFF);
			short cLen = (short) (apduBuf[7] & 0xFF);

			// Check ename0 must be printable ASCII without symbols and suitable length
			if (e0Len > FS_MAX_ENAME0_LEN) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}

			if (!Codec.isInputAllowable(apduBuf, (short) 8, e0Len, false)) {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}

			// Ensure ename1 and data has suitable length
			if (fsType == FS_FLAG_TYPE_ORGANIZER) {
				// Organizer must have ENAME1 == 4 which is the timestamp for the event
				if (e1Len != 4 || cLen > FS_MAX_CONTENT) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
			} else {
				// Everything else, the ENAME1 length and content length are free to be used
				if (e1Len > FS_MAX_ENAME1_LEN || cLen > FS_MAX_CONTENT) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
			}

			//
			if (fsType == FS_FLAG_TYPE_OTP) {
				// ENAME1 allows ASCII with symbols. Content can be any bytes due to storing
				// binary OTP keys
				if (!Codec.isInputAllowable(apduBuf, (short) (8 + e0Len), e1Len, true)) {
					ISOException.throwIt(ISO7816.SW_DATA_INVALID);
				}
			} else if (fsType == FS_FLAG_TYPE_ORGANIZER) {
				// ENAME1 is a 4 byte UNIX timestamp and may allow any bytes. The content can be
				// printable ASCII with symbols
				if (!Codec.isInputAllowable(apduBuf, (short) (8 + e0Len + e1Len), cLen, true)) {
					ISOException.throwIt(ISO7816.SW_DATA_INVALID);
				}
			} else {
				// Everything else, the ENAME1 and Content can be printable ASCII with symbols
				if (!Codec.isInputAllowable(apduBuf, (short) (8 + e0Len), (short) (e1Len + cLen), true)) {
					ISOException.throwIt(ISO7816.SW_DATA_INVALID);
				}
			}

			// Put data accordingly
			if (!setRecord(fsType, apduBuf, (short) 8, e0Len, apduBuf, (short) (8 + e0Len), e1Len, apduBuf,
					(short) (8 + e0Len + e1Len), cLen, b0, (short) 0)) {
				ISOException.throwIt(SW_FS_ERROR);
			}
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
	}

	private boolean isActiveFromFlag(byte flag) {
		if ((flag & FS_FLAG_ISACTIVE) >> 7 == (byte) 0x01)
			return true;
		return false;
	}

	private boolean isAuthNeededFromFlag(byte flag) {
		if ((flag & FS_FLAG_REQUIRE_AUTH) >> 6 == (byte) 0x01)
			return true;
		return false;
	}

	private boolean isHiddenTillAuthFromFlag(byte flag) {
		if (((flag & FS_FLAG_HIDE_UNLESS_AUTH) >> 5 == (byte) 0x01) && isAuthNeededFromFlag(flag))
			return true;
		return false;
	}

	private byte getTypeFromFlag(byte flag) {
		return (byte) (flag & 0x0F);
	}

	private short getRecordLocOffset(short recPos) {
		return (short) (recPos * FS_MAX_RECORD);
	}

	private short countTotalRecords() {
		short ttlCount = 0;
		for (short i = 0; i < FS_TOTAL_RECORDS; i++) {
			if (fs[(short) (getRecordLocOffset(i) + FS_OFF_FLAG_SETTING)] != (byte) 0x00)
				ttlCount++;
		}
		return ttlCount;
	}

	private short countFreeRecords() {
		return (short) (64 - countTotalRecords());
	}

	private short countRecordByType(byte type) {
		short ttlCount = 0;
		for (short i = 0; i < 64; i++) {
			if (getTypeFromFlag(fs[(short) (getRecordLocOffset(i) + FS_OFF_FLAG_SETTING)]) == type)
				ttlCount++;
		}
		return ttlCount;
	}

	private short searchRecordLocOffsetWithEName0AndType(byte type, byte[] ename0, short off, short len) {
		byte currType;
		short currLoc;
		short currENameLen;
		for (short i = 0; i < 64; i++) {
			currLoc = getRecordLocOffset(i);
			currType = getTypeFromFlag(fs[(short) (currLoc + FS_OFF_FLAG_SETTING)]);
			currENameLen = (short) (fs[(short) (currLoc + FS_OFF_FLAG_ENAME0_LEN)] & 0xFF);
			if (currType == type && currENameLen == len) {
				if (Util.arrayCompare(fs, (short) (currLoc + FS_OFF_ENAME0), ename0, off, len) == 0)
					return currLoc;
			}
		}
		return -1;
	}

	private short searchRecordLocWithEName0AndType(byte type, byte[] ename0, short off, short len) {
		byte currType;
		short currLoc;
		short currENameLen;
		for (short i = 0; i < 64; i++) {
			currLoc = getRecordLocOffset(i);
			currType = getTypeFromFlag(fs[(short) (currLoc + FS_OFF_FLAG_SETTING)]);
			currENameLen = (short) (fs[(short) (currLoc + FS_OFF_FLAG_ENAME0_LEN)] & 0xFF);
			if (currType == type && currENameLen == len) {
				if (Util.arrayCompare(fs, (short) (currLoc + FS_OFF_ENAME0), ename0, off, len) == 0)
					return i;
			}
		}
		return -1;
	}

	private short searchRecordLocOffsetWithTypeIndex(byte type, short index) {
		byte currType;
		short currLoc;
		short currTypeIndex = 0;
		for (short i = 0; i < 64; i++) {
			currLoc = getRecordLocOffset(i);
			currType = getTypeFromFlag(fs[(short) (currLoc + FS_OFF_FLAG_SETTING)]);
			if (currType == type) {
				if (index == currTypeIndex) {
					return currLoc;
				}
				currTypeIndex++;
			}
		}
		return -1;
	}

	private short listRecordLocIndexWithType(byte type, byte[] output, short outOff) {
		byte currType;
		short currLoc;
		short totalRecords = 0;
		for (short i = 0; i < 64; i++) {
			currLoc = getRecordLocOffset(i);
			currType = getTypeFromFlag(fs[(short) (currLoc + FS_OFF_FLAG_SETTING)]);
			if (currType == type) {
				output[(short) (outOff + totalRecords)] = (byte) (i & 0xFF);
				totalRecords++;
			}
		}
		return totalRecords;
	}

	private short getEName0FromLocOff(short loc, byte[] output, short off) {
		short eName0Len = (short) (fs[(short) (loc + FS_OFF_FLAG_ENAME0_LEN)] & 0xFF);
		Util.arrayCopyNonAtomic(fs, (short) (loc + FS_OFF_ENAME0), output, off, eName0Len);
		return eName0Len;
	}

	private short getEName1FromLocOff(short loc, byte[] output, short off) {
		short eName1Len = (short) (fs[(short) (loc + FS_OFF_FLAG_ENAME1_LEN)] & 0xFF);
		Util.arrayCopyNonAtomic(fs, (short) (loc + FS_OFF_ENAME1), output, off, eName1Len);
		return eName1Len;
	}

	private short getContentFromLocOff(short loc, byte[] output, short off) {
		short contentLen = (short) (fs[(short) (loc + FS_OFF_FLAG_CONTENT_LEN)] & 0xFF);
		Util.arrayCopyNonAtomic(fs, (short) (loc + FS_OFF_CONTENT), output, off, contentLen);
		return contentLen;
	}

	private short getEmptyRecordLoc() {
		short currLoc;
		for (short i = 0; i < 64; i++) {
			currLoc = getRecordLocOffset(i);
			if (getTypeFromFlag(fs[(short) (currLoc + FS_OFF_FLAG_SETTING)]) == (byte) 0x00) {
				return i;
			}
		}
		return (short) -1;
	}

	private boolean deleteRecord(byte type, byte[] ename0, short off, short len) {
		short currLoc = searchRecordLocOffsetWithEName0AndType(type, ename0, off, len);
		if (currLoc != (short) -1) {
			JCSystem.beginTransaction();
			currLoc = getRecordLocOffset(currLoc);
			Util.arrayFillNonAtomic(fs, currLoc, FS_MAX_RECORD, (byte) 0x00);
			JCSystem.commitTransaction();
			return true;
		}
		return false;
	}

	private boolean setRecord(byte type, byte[] ename0, short e0Off, short e0Len, byte[] ename1, short e1Off,
			short e1Len, byte[] content, short cOff, short cLen, byte[] buff, short bOff) {
		short currLoc = -1;
		boolean overwrite = false;
		currLoc = searchRecordLocWithEName0AndType(type, ename0, e0Off, e0Len);

		if (currLoc == -1) {
			// Scenario - New record. Checking must be done prior to setting record.
			// Get empty record block
			currLoc = getEmptyRecordLoc();

			// No slots available
			if (currLoc == -1) {
				return false;
			}

			// Set record into new record block
			fs[(short) (getRecordLocOffset(currLoc) + FS_OFF_FLAG_SETTING)] = type;
			overwrite = true;
		}

		// Overwrites records
		if (ename0 != null && e0Len > 0 && overwrite) {
			fs[(short) (getRecordLocOffset(currLoc) + FS_OFF_FLAG_ENAME0_LEN)] = (byte) (e0Len & 0xFF);
			Util.arrayFillNonAtomic(fs, (short) (getRecordLocOffset(currLoc) + FS_OFF_ENAME0), FS_MAX_ENAME0_LEN,
					(byte) 0x00);
			Util.arrayCopy(ename0, e0Off, fs, (short) (getRecordLocOffset(currLoc) + FS_OFF_ENAME0), e0Len);
		}
		if (ename1 != null && e1Len > 0) {
			fs[(short) (getRecordLocOffset(currLoc) + FS_OFF_FLAG_ENAME1_LEN)] = (byte) (e1Len & 0xFF);
			Util.arrayFillNonAtomic(fs, (short) (getRecordLocOffset(currLoc) + FS_OFF_ENAME1), FS_MAX_ENAME1_LEN,
					(byte) 0x00);
			Util.arrayCopy(ename1, e1Off, fs, (short) (getRecordLocOffset(currLoc) + FS_OFF_ENAME1), e1Len);
		}
		if (content != null && cLen > 0) {
			fs[(short) (getRecordLocOffset(currLoc) + FS_OFF_FLAG_CONTENT_LEN)] = (byte) (cLen & 0xFF);
			Util.arrayFillNonAtomic(fs, (short) (getRecordLocOffset(currLoc) + FS_OFF_CONTENT), FS_MAX_CONTENT,
					(byte) 0x00);
			if (!cryptoContent(Cipher.MODE_ENCRYPT, currLoc, content, cOff, buff, bOff)) {
				return false;
			}
		}

		return true;
	}

	private short getRecordEName0List(byte type, short offIndex, short recordCount, byte[] output, short off) {
		short ttlCount = -1;
		short ttlBytes = -1;
		short currLoc;
		short currIndexCnt = 0;
		short currEName0Len;

		// Check recordCount <= 6 and > 0
		if (recordCount <= 6 && recordCount > 0) {
			ttlCount = 0;
			ttlBytes = 1;

			// List record by type from offIndex start point
			// <ttlCount><rec0Len><rec0EName0> ... <recNLen><recNEName0>
			for (short i = 0; i < 64; i++) {
				currLoc = getRecordLocOffset(i);

				// Check is correct type
				if (getTypeFromFlag(fs[(short) (currLoc + FS_OFF_FLAG_SETTING)]) == (byte) 0x00) {

					// Check index count and record count are within params
					if (currIndexCnt >= offIndex && ttlCount < recordCount) {
						// Get EName0 and set into recNEName0
						currEName0Len = getEName0FromLocOff(currLoc, output, (short) (ttlBytes + off + 1));

						// Set recNLen
						output[(short) (ttlBytes + off)] = (byte) (currEName0Len & 0xFF);
						ttlBytes += currEName0Len;
						ttlCount++;
					}
					currIndexCnt++;
				}
			}

			// Set total record count
			output[off] = (byte) (ttlCount & 0xFF);
		}

		return ttlBytes;
	}

	private boolean cryptoContent(byte mode, short recordLoc, byte[] data, short off, byte[] buff, short bOff) {
		// Generate IV by concatenating FSIV || recFlag || recEName0 || recEName1 and
		// retrieve first 16 bytes
		md.reset();
		md.update(fsIV, (short) 0, (short) fsIV.length);
		md.doFinal(fs, recordLoc, FS_OFF_CONTENT, buff, bOff);

		// Note: Flag for content length must already be set before calling encrypt or
		// decrypt
		if (mode == Cipher.MODE_ENCRYPT) {
			// cryptoContent(Cipher.MODE_ENCRYPT, (short) (currLoc + FS_OFF_CONTENT),
			// content, cOff, buff, bOff))
			// Encrypt and sets content into FS
			cipherNoPad.init(fsKey, mode, buff, bOff, (short) 16);
			cipherNoPad.doFinal(data, off, FS_MAX_CONTENT, fs,
					(short) (getRecordLocOffset(recordLoc) + FS_OFF_CONTENT));
			return true;
		} else if (mode == Cipher.MODE_DECRYPT) {
			// Decrypt and return decrypted content
			cipherNoPad.init(fsKey, mode, buff, bOff, (short) 16);
			cipherNoPad.doFinal(fs, (short) (getRecordLocOffset(recordLoc) + FS_OFF_CONTENT), FS_MAX_CONTENT, data,
					off);
			return true;
		}
		return false;
	}

	/**
	 * Processes an incoming APDU.
	 * 
	 * @see APDU
	 * @param apdu the incoming APDU
	 */
	public void process(APDU apdu) {
		if (selectingApplet()) {
			return;
		}

		byte[] buffer = apdu.getBuffer();
		byte ins = buffer[ISO7816.OFFSET_INS];

		if (api == null && ins != (byte) 0x00) {
			ISOException.throwIt(SW_CARD_NOT_READY);
		}

		switch (ins) {
		case (byte) 0x00:
			if (api == null)
				initAPI(buffer);
			break;
		case (byte) 0x01:
			if (pubKey.isInitialized()) {
				short len = pubKey.getW(buffer, (short) 0);
				apdu.setOutgoingAndSend((short) 0, len);
			}
			break;
		case (byte) 0x02:
			Util.arrayCopyNonAtomic(fs, (short) 0, buffer, (short) 0, (short) 256);
			apdu.setOutgoingAndSend((short) 0, (short) 256);
			break;
//			// Secure echo test.
//			sb[0] = apdu.setIncomingAndReceive();
//
//			if (sb[0] <= 240) {
//				// Buffer off packet
//				Util.arrayCopyNonAtomic(buffer, (short) 0, b1, (short) 0, (short) 4);
//				Util.arrayCopyNonAtomic(buffer, (short) 5, b0, (short) 0, sb[0]);
//
//				// Decrypt incoming.
//				sb[0] = securePacketProcess(Cipher.MODE_DECRYPT, b1, (short) 0, (short) 4, b0, (short) 0, sb[0], sb[1],
//						buffer);
//
//				if (sb[0] != (short) -1) {
//					// Copy decrypted data to b0 buffer for encryption
//					Util.arrayCopyNonAtomic(buffer, (short) 0, b0, (short) 0, sb[0]);
//
//					// Re-encrypt and send back
//					Codec.shortToBytes(ISO7816.SW_NO_ERROR, b1, (short) 0);
//					sb[0] = securePacketProcess(Cipher.MODE_ENCRYPT, b1, (short) 0, (short) 2, b0, (short) 0, sb[0],
//							sb[1], buffer);
//					if (sb[0] != (short) -1) {
//						apdu.setOutgoingAndSend((short) 0, sb[0]);
//					} else {
//						ISOException.throwIt(SW_SCHANNEL_ERROR);
//					}
//				} else {
//					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
//				}
//			} else {
//				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
//			}
//			break;
		case (byte) 0x03:
			fsGet(apdu, buffer);
			break;
		case (byte) 0x04:
			fsPut(apdu, buffer);
			break;
		case (byte) 0x10:
			mainMenu(apdu, buffer);
			break;
		case (byte) 0xFE:
			if (sessKey.isInitialized()) {
				short len = sessKey.getKey(buffer, (short) 0);
				apdu.setOutgoingAndSend((short) 0, len);
			}
			break;
		case (byte) 0xFF:
			secureChannel(apdu, buffer);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			break;
		}
	}
}
