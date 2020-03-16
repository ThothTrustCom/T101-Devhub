/**
 * BSD-3-Clause
 * 
 * Copyright 2020 ThothTrust Pte Ltd.
 * 
 * Refer to LICENSE file for full license text.
 */
package org.thothtrust.sc.thothpgp;

import org.thothtrust.sc.certstore.CertStoreAPI;
import org.thothtrust.sc.thothpgp.Common;
import org.thothtrust.sc.thothpgp.Constants;
import org.thothtrust.sc.thothpgp.ECCurves;
import org.thothtrust.sc.thothpgp.PGPKey;
import org.thothtrust.sc.thothpgp.Persistent;
import org.thothtrust.sc.thothpgp.SecureMessaging;
import org.thothtrust.sc.thothpgp.Transients;
import KM101.T101OpenAPI;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * Modified version of SmartPGP by ANSSI. <br>
 * <br>
 * Original SmartPGP source code: <br>
 * https://github.com/ANSSI-FR/SmartPGP <br>
 * <br>
 * Modified version will support the T101 Open API functionalities with
 * cryptographic processing, key storage, user management and secure GUI to be
 * processed and handled via the T101 features. <br>
 * <br>
 * 
 * @author ANSSI
 * @author ThothTrust Pte Ltd.
 */
public class ThothPGPApplet extends Applet implements AppletEvent {

	private ECCurves ec = null;
	private Persistent data = null;
	private SecureMessaging sm = null;
	private Transients transients = null;
	public static Cipher cipher_aes_cbc_nopad = null;
	public static RandomData random_data = null;
	public static T101OpenAPI api = null;
	public static CertStoreAPI csapi = null;
	public static APIShim apishim = null;
	public AID apiAID = null;
	public AID csapiAID = null;
	public static byte[] serverAID = new byte[] { (byte) 0x4B, (byte) 0x4D, (byte) 0x31, (byte) 0x30, (byte) 0x31,
			(byte) 0x00 };
	public static byte[] csServerAID = new byte[] { (byte) 0x54, (byte) 0x54, (byte) 0x43, (byte) 0x52, (byte) 0x53,
			(byte) 0xFF };
	public static byte[] debug = new byte[12];

	public ThothPGPApplet() {
		cipher_aes_cbc_nopad = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		random_data = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		ec = new ECCurves();
		data = new Persistent();
		transients = new Transients();
		sm = new SecureMessaging(transients);
	}

	public static final void install(byte[] buf, short off, byte len) {
		new ThothPGPApplet().register(buf, (short) (off + 1), buf[off]);
	}

	public void uninstall() {
		destroyEnv();
	}

	public boolean destroyEnv() {
		if (api != null) {
			api.destroyAOCContainer();
			return true;
		}

		return false;
	}

	private final void initAPI(byte[] apdubuf) {
		if (api == null && csapi == null) {
			try {
				apiAID = JCSystem.lookupAID(serverAID, (short) 0, (byte) serverAID.length);
				csapiAID = JCSystem.lookupAID(csServerAID, (short) 0, (byte) csServerAID.length);
			} catch (Exception e) {
				ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
			}
			if (apiAID != null && csapiAID != null) {
				api = (T101OpenAPI) JCSystem.getAppletShareableInterfaceObject(apiAID, (byte) 0);
				csapi = (CertStoreAPI) JCSystem.getAppletShareableInterfaceObject(csapiAID, (byte) 0);
				if (api == null && csapi == null) {
					ISOException.throwIt(ISO7816.SW_APPLET_SELECT_FAILED);
				}
				apishim = new APIShim();
				api.destroyAOCContainer();
				apishim.initEnv(apdubuf);
			} else {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
		}
	}

	private final PGPKey currentTagOccurenceToKey() {
		switch (transients.currentTagOccurrence()) {
		case 0:
			return data.pgp_keys[Persistent.PGP_KEYS_OFFSET_AUT];
		case 1:
			return data.pgp_keys[Persistent.PGP_KEYS_OFFSET_DEC];
		case 2:
			return data.pgp_keys[Persistent.PGP_KEYS_OFFSET_SIG];
		case 3:
			return sm.static_key;
		default:
			ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
			return null;
		}
	}

	private final byte currentTagOccurenceToKeyInd() {
		switch (transients.currentTagOccurrence()) {
		case 0:
			return Persistent.PGP_KEYS_OFFSET_AUT;
		case 1:
			return Persistent.PGP_KEYS_OFFSET_DEC;
		case 2:
			return Persistent.PGP_KEYS_OFFSET_SIG;
		case 3:
			return (byte) 0xFF;
		default:
			debug[0] = (byte) 0x32;
//			ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
			ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0x32));
			return (byte) 0x0F;
		}
	}

	private final void prepareChainingInput(final byte[] apdubuf) {
		short tmp;

		tmp = transients.outputLength();
		if (tmp > 0) {
			Util.arrayFillNonAtomic(transients.buffer, transients.outputStart(), tmp, (byte) 0);
		}
		transients.setChainingOutput(false);
		transients.setOutputStart((short) 0);
		transients.setOutputLength((short) 0);

		if (transients.chainingInput()) {
			if ((apdubuf[ISO7816.OFFSET_INS] != transients.chainingInputIns())
					|| (apdubuf[ISO7816.OFFSET_P1] != transients.chainingInputP1())
					|| (apdubuf[ISO7816.OFFSET_P2] != transients.chainingInputP2())) {
				transients.setChainingInput(false);
				transients.setChainingInputLength((short) 0);
				ISOException.throwIt(Constants.SW_CHAINING_ERROR);
				return;
			}
			if ((apdubuf[ISO7816.OFFSET_CLA] & Constants.CLA_MASK_CHAINING) != Constants.CLA_MASK_CHAINING) {
				transients.setChainingInput(false);
			}
		} else {
			tmp = transients.chainingInputLength();
			if (tmp > 0) {
				Util.arrayFillNonAtomic(transients.buffer, (short) 0, tmp, (byte) 0);
			}
			transients.setChainingInputLength((short) 0);

			if ((apdubuf[ISO7816.OFFSET_CLA] & Constants.CLA_MASK_CHAINING) == Constants.CLA_MASK_CHAINING) {
				transients.setChainingInputIns(apdubuf[ISO7816.OFFSET_INS]);
				transients.setChainingInputP1(apdubuf[ISO7816.OFFSET_P1]);
				transients.setChainingInputP2(apdubuf[ISO7816.OFFSET_P2]);
				transients.setChainingInput(true);
			}
		}
	}

	private final void receiveData(final APDU apdu) {
		final byte[] apdubuf = apdu.getBuffer();

		short blen = apdu.setIncomingAndReceive();

		final short lc = apdu.getIncomingLength();
		final short offcdata = ISO7816.OFFSET_CDATA;

		short off = transients.chainingInputLength();

		if ((short) (off + lc) > Constants.INTERNAL_BUFFER_MAX_LENGTH) {
			transients.setChainingInput(false);
			transients.setChainingInputLength((short) 0);
			ISOException.throwIt(Constants.SW_MEMORY_FAILURE);
			return;
		}

		while (blen > 0) {
			off = Util.arrayCopyNonAtomic(apdubuf, offcdata, transients.buffer, off, blen);
			blen = apdu.receiveBytes(offcdata);
		}

		transients.setChainingInputLength(off);
	}

	private final void sensitiveData() {
		final byte proto = APDU.getProtocol();

		if (((proto & APDU.PROTOCOL_MEDIA_MASK) == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A)
				|| ((proto & APDU.PROTOCOL_MEDIA_MASK) == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B)) {
			if (sm.isInitialized() && !transients.secureMessagingOk()) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				return;
			}
		}
	}

	private final void assertAdmin() {
		if (!transients.userPinMode83()) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
	}

	private final void assertUserMode81() {
		if (!transients.userPinMode81()) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
	}

	private final void assertUserMode82() {
		if (!transients.userPinMode82()) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
	}

	private final short writePwStatus(final byte[] buf, short off) {
		buf[off++] = (byte) (data.user_pin_force_verify_signature ? 0x00 : 0x01);

		if (data.keyDerivationIsActive()) {
			final byte size = data.keyDerivationSize();
			buf[off++] = size;
			buf[off++] = size;
			buf[off++] = size;
		} else {
			buf[off++] = Constants.USER_PIN_MAX_SIZE;
			buf[off++] = Constants.USER_PUK_MAX_SIZE;
			buf[off++] = Constants.ADMIN_PIN_MAX_SIZE;
		}

		buf[off++] = -1; // data.user_pin.getTriesRemaining();
		buf[off++] = -1; // data.user_puk.getTriesRemaining();
		buf[off++] = -1; // data.admin_pin.getTriesRemaining();

		return off;
	}

	private final short writeKeyFingerprints(final byte[] buf, short off) {
		for (byte i = 0; i < data.pgp_keys.length; ++i) {
			off = data.pgp_keys[i].fingerprint.write(buf, off);
		}
		return off;
	}

	private final short writeCaFingerprints(final byte[] buf, short off) {
		for (byte i = 0; i < data.fingerprints.length; ++i) {
			off = data.fingerprints[i].write(buf, off);
		}
		return off;
	}

	private final short getKeyGenerationDates(final byte[] buf, short off, byte[] apduBuffer) {
		ThothPGPApplet.apishim.getObjectCreationTS(Persistent.PGP_KEYS_OFFSET_AUT, apduBuffer);
		off = Util.arrayCopyNonAtomic(apduBuffer, (short) 0, buf, off, Constants.GENERATION_DATE_SIZE);
		ThothPGPApplet.apishim.getObjectCreationTS(Persistent.PGP_KEYS_OFFSET_DEC, apduBuffer);
		off = Util.arrayCopyNonAtomic(apduBuffer, (short) 0, buf, off, Constants.GENERATION_DATE_SIZE);
		ThothPGPApplet.apishim.getObjectCreationTS(Persistent.PGP_KEYS_OFFSET_SIG, apduBuffer);
		off = Util.arrayCopyNonAtomic(apduBuffer, (short) 0, buf, off, Constants.GENERATION_DATE_SIZE);
		return off;
	}

	private final void processSelectData(final short lc, final byte p1, final byte p2) {
		if ((lc < 5) || (lc > 6)) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return;
		}

		if ((p1 < 0) || (p1 > 3) || (p2 != 0x04)) {
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			return;
		}

		final byte[] buf = transients.buffer;

		if ((buf[0] != (byte) 0x60) || (buf[1] != (byte) (lc - 2)) || (buf[2] != (byte) 0x5C)
				|| (buf[3] != (byte) (lc - 2 - 2))) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		transients.setCurrentTagOccurrence(p1);

		if (buf[3] == 1) {
			transients.setCurrentTag(buf[4]);
		} else if (buf[3] == 2) {
			transients.setCurrentTag(Util.getShort(buf, (short) 4));
		}
	}

	private final short processGetData(final byte p1, final byte p2, byte[] apduBuffer) {

		final short tag = Util.makeShort(p1, p2);
		short off = 0;
		short tlen = 0;

		if (transients.currentTag() == 0) {
			transients.setCurrentTag(tag);
			transients.setCurrentTagOccurrence((byte) 0);
		} else if (transients.currentTag() != tag) {
			transients.setCurrentTagOccurrence((byte) 0);
		}

		final byte[] buf = transients.buffer;
		PGPKey k;

		switch (tag) {
		case Constants.TAG_AID:
			off = (short) (off + JCSystem.getAID().getBytes(buf, off));
			break;

		case Constants.TAG_LOGIN:
			off = Util.arrayCopyNonAtomic(data.login, (short) 0, buf, off, data.login_length);
			break;

		case Constants.TAG_URL:
			off = Util.arrayCopyNonAtomic(data.url, (short) 0, buf, off, data.url_length);
			break;

		case Constants.TAG_PRIVATE_DO_0101:
			off = Util.arrayCopyNonAtomic(data.do_0101, (short) 0, buf, off, data.do_0101_length);
			break;

		case Constants.TAG_PRIVATE_DO_0102:
			off = Util.arrayCopyNonAtomic(data.do_0102, (short) 0, buf, off, data.do_0102_length);
			break;

		case Constants.TAG_PRIVATE_DO_0103:
			assertUserMode82();
			off = Util.arrayCopyNonAtomic(data.do_0103, (short) 0, buf, off, data.do_0103_length);
			break;

		case Constants.TAG_PRIVATE_DO_0104:
			assertAdmin();
			off = Util.arrayCopyNonAtomic(data.do_0104, (short) 0, buf, off, data.do_0104_length);
			break;

		case Constants.TAG_KEY_FINGERPRINTS:
			off = writeKeyFingerprints(buf, off);
			break;

		case Constants.TAG_CA_FINGERPRINTS:
			off = writeCaFingerprints(buf, off);
			break;
		case Constants.TAG_KEY_GENERATION_DATES:
			off = getKeyGenerationDates(buf, off, apduBuffer);
			break;

		case Constants.TAG_HISTORICAL_BYTES_CARD_SERVICE_CARD_CAPABILITIES:
			off = Util.arrayCopyNonAtomic(Constants.HISTORICAL_BYTES, (short) 0, buf, off,
					(byte) Constants.HISTORICAL_BYTES.length);
			break;

		case Constants.TAG_CARDHOLDER_RELATED_DATA:
			buf[off++] = (byte) 0x5B;
			off = Common.writeLength(buf, off, data.name_length);
			off = Util.arrayCopyNonAtomic(data.name, (short) 0, buf, off, data.name_length);

			off = Util.setShort(buf, off, (short) 0x5f2d);
			off = Common.writeLength(buf, off, data.lang_length);
			off = Util.arrayCopyNonAtomic(data.lang, (short) 0, buf, off, data.lang_length);

			off = Util.setShort(buf, off, (short) 0x5f35);
			buf[off++] = (byte) 0x01;
			buf[off++] = data.sex;
			break;

		case Constants.TAG_EXTENDED_LENGTH_INFORMATION:
			off = Util.setShort(buf, off, Constants.TAG_EXTENDED_LENGTH_INFORMATION);
			off = Common.writeLength(buf, off, (short) 8);
			buf[off++] = (byte) 0x02;
			buf[off++] = (byte) 0x02;
			off = Util.setShort(buf, off, (short) 256); // Constants.APDU_MAX_LENGTH = 256;
			buf[off++] = (byte) 0x02;
			buf[off++] = (byte) 0x02;
			off = Util.setShort(buf, off, (short) 256);
			break;

		case Constants.TAG_ALGORITHM_ATTRIBUTES_SIG:
			buf[off++] = (byte) 0xc1;
			k = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_SIG];
			off = Common.writeLength(buf, off, k.attributes_length);
			off = Util.arrayCopyNonAtomic(k.attributes, (short) 0, buf, off, k.attributes_length);
			break;

		case Constants.TAG_ALGORITHM_ATTRIBUTES_DEC:
			buf[off++] = (byte) 0xc2;
			k = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_DEC];
			off = Common.writeLength(buf, off, k.attributes_length);
			off = Util.arrayCopyNonAtomic(k.attributes, (short) 0, buf, off, k.attributes_length);
			break;

		case Constants.TAG_ALGORITHM_ATTRIBUTES_AUT:
			buf[off++] = (byte) 0xc3;
			k = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_AUT];
			off = Common.writeLength(buf, off, k.attributes_length);
			off = Util.arrayCopyNonAtomic(k.attributes, (short) 0, buf, off, k.attributes_length);
			break;

		case Constants.TAG_ALGORITHM_ATTRIBUTES_SM:
			buf[off++] = (byte) 0xd4;
			k = sm.static_key;
			off = Common.writeLength(buf, off, k.attributes_length);
			off = Util.arrayCopyNonAtomic(k.attributes, (short) 0, buf, off, k.attributes_length);
			break;

		case Constants.TAG_APPLICATION_RELATED_DATA:
			tlen = (short) (1 + 1 + Constants.EXTENDED_CAPABILITIES.length + 1 + 1
					+ data.pgp_keys[Persistent.PGP_KEYS_OFFSET_SIG].attributes_length + 1 + 1
					+ data.pgp_keys[Persistent.PGP_KEYS_OFFSET_DEC].attributes_length + 1 + 1
					+ data.pgp_keys[Persistent.PGP_KEYS_OFFSET_AUT].attributes_length + 1 + 1 + 7 + 1 + 1
					+ (3 * Constants.FINGERPRINT_SIZE) + 1 + 1 + (3 * Constants.FINGERPRINT_SIZE) + 1 + 1
					+ (3 * Constants.GENERATION_DATE_SIZE));

			final byte aid_length = JCSystem.getAID().getBytes(buf, off);

			buf[off++] = (byte) Constants.TAG_APPLICATION_RELATED_DATA;
			off = Common.writeLength(buf, off,
					(short) (tlen + 1 + aid_length + 2 + 1 + Constants.HISTORICAL_BYTES.length));

			buf[off++] = (byte) Constants.TAG_AID;
			off = Common.writeLength(buf, off, aid_length);
			off += JCSystem.getAID().getBytes(buf, off);
			off = Util.setShort(buf, off, Constants.TAG_HISTORICAL_BYTES_CARD_SERVICE_CARD_CAPABILITIES);
			off = Common.writeLength(buf, off, (short) Constants.HISTORICAL_BYTES.length);
			off = Util.arrayCopyNonAtomic(Constants.HISTORICAL_BYTES, (short) 0, buf, off,
					(byte) Constants.HISTORICAL_BYTES.length);

			buf[off++] = (byte) 0x73;
			off = Common.writeLength(buf, off, tlen);
			buf[off++] = (byte) 0xc0;
			off = Common.writeLength(buf, off, (short) Constants.EXTENDED_CAPABILITIES.length);
			off = Util.arrayCopyNonAtomic(Constants.EXTENDED_CAPABILITIES, (short) 0, buf, off,
					(short) Constants.EXTENDED_CAPABILITIES.length);

			buf[off++] = (byte) 0xc1;
			k = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_SIG];
			off = Common.writeLength(buf, off, k.attributes_length);
			off = Util.arrayCopyNonAtomic(k.attributes, (short) 0, buf, off, k.attributes_length);

			buf[off++] = (byte) 0xc2;
			k = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_DEC];
			off = Common.writeLength(buf, off, k.attributes_length);
			off = Util.arrayCopyNonAtomic(k.attributes, (short) 0, buf, off, k.attributes_length);

			buf[off++] = (byte) 0xc3;
			k = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_AUT];
			off = Common.writeLength(buf, off, k.attributes_length);
			off = Util.arrayCopyNonAtomic(k.attributes, (short) 0, buf, off, k.attributes_length);

			buf[off++] = (byte) 0xc4;
			buf[off++] = 7;
			off = writePwStatus(buf, off);

			buf[off++] = (byte) 0xc5;
			off = Common.writeLength(buf, off, (short) (3 * Constants.FINGERPRINT_SIZE));
			off = writeKeyFingerprints(buf, off);

			buf[off++] = (byte) 0xc6;
			off = Common.writeLength(buf, off, (short) (3 * Constants.FINGERPRINT_SIZE));
			off = writeCaFingerprints(buf, off);

			buf[off++] = (byte) 0xcd;
			off = Common.writeLength(buf, off, (short) (3 * Constants.GENERATION_DATE_SIZE));
			off = getKeyGenerationDates(buf, off, apduBuffer);

			Common.writeLength(buf, (short) 1, (short) (off - 3));
			break;

		case Constants.TAG_PW_STATUS:
			off = writePwStatus(buf, off);
			break;

		case Constants.TAG_SECURITY_SUPPORT_TEMPLATE:
			buf[off++] = (byte) 0x93;
			buf[off++] = (byte) data.digital_signature_counter.length;
			off = Util.arrayCopyNonAtomic(data.digital_signature_counter, (short) 0, buf, off,
					(byte) data.digital_signature_counter.length);
			break;

		case Constants.TAG_CARDHOLDER_CERTIFICATE:
			k = currentTagOccurenceToKey();

			if (k == null) {
				ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
				return 0;
			}

			off = apishim.readCert(currentTagOccurenceToKeyInd(), buf, off, (short) 0,
					apishim.certLength(currentTagOccurenceToKeyInd()));
			break;

		case Constants.TAG_KEY_INFORMATION:
			buf[off++] = (byte) 0xde;
			buf[off++] = (byte) 0x06; /* len */
			buf[off++] = (byte) 0x01;
			buf[off++] = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_SIG].keyInformation();
			buf[off++] = (byte) 0x02;
			buf[off++] = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_DEC].keyInformation();
			buf[off++] = (byte) 0x03;
			buf[off++] = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_AUT].keyInformation();
			break;

		case Constants.TAG_KEY_DERIVATION_FUNCTION:
			off = Util.arrayCopyNonAtomic(data.key_derivation_function, (short) 0, buf, off,
					data.key_derivation_function_length);
			break;

		case Constants.TAG_ALGORITHM_INFORMATION:
			off = Common.writeAlgorithmInformation(ec, (byte) 0xc1, false, buf, off); /* SIG */
			off = Common.writeAlgorithmInformation(ec, (byte) 0xc2, true, buf, off); /* DEC */
			off = Common.writeAlgorithmInformation(ec, (byte) 0xc3, false, buf, off); /* AUT */
			break;

		case Constants.TAG_SECURE_MESSAGING_CERTIFICATE:
			off = apishim.readCert((byte) 0xFF, buf, off, (short) 0, apishim.certLength((byte) 0xFF));
			break;

		default:
			ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
			return 0;
		}

		return off;
	}

	private final short processGetNextData(final byte p1, final byte p2) {

		if (Util.makeShort(p1, p2) != Constants.TAG_CARDHOLDER_CERTIFICATE) {
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			return 0;
		}

		final PGPKey k = currentTagOccurenceToKey();

		if (k == null) {
			debug[0] = (byte) 0x35;
//			ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
			ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0x35));
			return 0;
		}

		transients.setCurrentTagOccurrence((byte) (transients.currentTagOccurrence() + 1));

		return apishim.readCert(currentTagOccurenceToKeyInd(), transients.buffer, (short) 0, (short) 0,
				apishim.certLength(currentTagOccurenceToKeyInd()));
	}

	private final void processVerify(short lc, final byte p1, final byte p2, byte[] apduBuffer) {

		sensitiveData();

		if (p1 == 0) {

			// No PIN retries checking service available.
			switch (p2) {
			case (byte) 0x81:
			case (byte) 0x82:
				debug[0] = (byte) 0x41;
				if (p2 == (byte) 0x81) {
					transients.setUserPinMode81(false);
				} else {
					transients.setUserPinMode82(false);
				}
				debug[0] = (byte) 0x42;
				// Login normal user and get tries remaining
				if (ThothPGPApplet.apishim.loginNormalUserAndGetTries(apduBuffer) == (short) -1) {
					debug[0] = (byte) 0x43;
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
					return;
				}
				debug[0] = (byte) 0x44;
				if (p2 == (byte) 0x81) {
					transients.setUserPinMode81(true);
				} else {
					transients.setUserPinMode82(true);
				}
				return;

			case (byte) 0x83:
				debug[0] = (byte) 0x45;
				// Login admin user
				transients.setUserPinMode83(false);
				if (ThothPGPApplet.apishim.loginAdminUserAndGetTries(apduBuffer) == (short) -1) {
					debug[0] = (byte) 0x46;
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
					return;
				}
				debug[0] = (byte) 0x47;
				transients.setUserPinMode83(true);
				return;

			default:
				debug[0] = (byte) 0x48;
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				return;
			}

		} else if (p1 == (byte) 0xff) {
			debug[0] = (byte) 0x49;
			if (lc != 0) {
				debug[0] = (byte) 0x4A;
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				return;
			}
			debug[0] = (byte) 0x4B;
			switch (p2) {
			case (byte) 0x81:
				debug[0] = (byte) 0x4C;
				transients.setUserPinMode81(false);
				return;

			case (byte) 0x82:
				debug[0] = (byte) 0x4D;
				transients.setUserPinMode82(false);
				return;

			case (byte) 0x83:
				debug[0] = (byte) 0x4E;
				transients.setUserPinMode83(false);
				return;

			default:
				debug[0] = (byte) 0x4F;
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				return;
			}
		}

		debug[0] = (byte) 0x46;
		ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		return;
	}

	private final void processChangeReferenceData(final short lc, final byte p1, final byte p2, byte[] apduBuffer) {

		sensitiveData();

		byte off;
		byte minlen;

		if (p1 != 0) {
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			return;
		}

		switch (p2) {
		case (byte) 0x81:
			// Normal user login and change pin
			transients.setUserPinMode81(false);
			transients.setUserPinMode82(false);
			if (!ThothPGPApplet.apishim.changeNormalUserPin(apduBuffer)) {
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				return;
			}
			break;

		case (byte) 0x83:
			// Admin user login and change pin
			transients.setUserPinMode83(false);
			if (!ThothPGPApplet.apishim.changeAdminPin(apduBuffer)) {
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				return;
			}
			break;

		default:
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			return;
		}
	}

	private final void processResetRetryCounter(final short lc, final byte p1, final byte p2, byte[] apduBuffer) {

		sensitiveData();

		byte off = 0;
		byte minlen;

		if (p2 != (byte) 0x81) {
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			return;
		}

		switch (p1) {
		case (byte) 0x00:

			transients.setUserPinMode81(false);
			transients.setUserPinMode82(false);

			// Login with PUK and reset normal user
			if (!ThothPGPApplet.apishim.pukResetNormalUserPin(apduBuffer)) {
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				return;
			}
			break;

		case (byte) 0x02:

			transients.setUserPinMode81(false);
			transients.setUserPinMode82(false);

			// Login with admin from front panel and reset normal user
			if (!ThothPGPApplet.apishim.adminResetNormalUserPin(apduBuffer)) {
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				return;
			}
			break;

		default:
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			return;
		}
	}

	private final void processPutData(final short lc, final byte p1, final byte p2, final boolean isOdd,
			byte[] apduBuffer) {

		sensitiveData();

		final byte[] buf = transients.buffer;

		PGPKey k = null;

		if (isOdd) {

			// Key Import. Function not supported.
			ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);

		} else {
			final short tag = Util.makeShort(p1, p2);

			if (transients.currentTag() == 0) {
				transients.setCurrentTag(tag);
				transients.setCurrentTagOccurrence((byte) 0);
			} else if (transients.currentTag() != tag) {
				transients.setCurrentTagOccurrence((byte) 0);
			}

			switch (tag) {
			case Constants.TAG_NAME:
				assertAdmin();
				if ((lc < 0) || (lc > Constants.NAME_MAX_LENGTH)) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					return;
				}
				JCSystem.beginTransaction();
				if (data.name_length > 0) {
					Util.arrayFillNonAtomic(data.name, (short) 0, data.name_length, (byte) 0);
				}
				Util.arrayCopyNonAtomic(buf, (short) 0, data.name, (short) 0, lc);
				data.name_length = (byte) lc;
				JCSystem.commitTransaction();
				break;

			case Constants.TAG_LOGIN:
				assertAdmin();
				if ((lc < 0) || (lc > Constants.specialDoMaxLength())) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					return;
				}
				JCSystem.beginTransaction();
				if (data.login_length > 0) {
					Util.arrayFillNonAtomic(data.login, (short) 0, data.login_length, (byte) 0);
				}
				Util.arrayCopyNonAtomic(buf, (short) 0, data.login, (short) 0, lc);
				data.login_length = lc;
				JCSystem.commitTransaction();
				break;

			case Constants.TAG_LANG:
				assertAdmin();
				if ((lc < Constants.LANG_MIN_LENGTH) || (lc > Constants.LANG_MAX_LENGTH)) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					return;
				}
				JCSystem.beginTransaction();
				if (data.lang_length > 0) {
					Util.arrayFillNonAtomic(data.lang, (short) 0, data.lang_length, (byte) 0);
				}
				Util.arrayCopyNonAtomic(buf, (short) 0, data.lang, (short) 0, lc);
				data.lang_length = (byte) lc;
				JCSystem.commitTransaction();
				break;

			case Constants.TAG_SEX:
				assertAdmin();
				if (lc != 1) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					return;
				}

				switch (buf[0]) {
				case Constants.SEX_MALE:
				case Constants.SEX_FEMALE:
				case Constants.SEX_NOT_ANNOUNCED:
					data.sex = buf[0];
					break;

				default:
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
					return;
				}
				break;

			case Constants.TAG_URL:
				assertAdmin();
				if ((lc < 0) || (lc > Constants.specialDoMaxLength())) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					return;
				}
				JCSystem.beginTransaction();
				if (data.url_length > 0) {
					Util.arrayFillNonAtomic(data.url, (short) 0, data.url_length, (byte) 0);
				}
				Util.arrayCopyNonAtomic(buf, (short) 0, data.url, (short) 0, lc);
				data.url_length = lc;
				JCSystem.commitTransaction();
				break;

			case Constants.TAG_PRIVATE_DO_0101:
				assertUserMode82();
				if ((lc < 0) || (lc > Constants.specialDoMaxLength())) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					return;
				}
				JCSystem.beginTransaction();
				if (data.do_0101_length > 0) {
					Util.arrayFillNonAtomic(data.do_0101, (short) 0, data.do_0101_length, (byte) 0);
				}
				Util.arrayCopyNonAtomic(buf, (short) 0, data.do_0101, (short) 0, lc);
				data.do_0101_length = lc;
				JCSystem.commitTransaction();
				break;

			case Constants.TAG_PRIVATE_DO_0102:
				assertAdmin();
				if ((lc < 0) || (lc > Constants.specialDoMaxLength())) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					return;
				}
				JCSystem.beginTransaction();
				if (data.do_0102_length > 0) {
					Util.arrayFillNonAtomic(data.do_0102, (short) 0, data.do_0102_length, (byte) 0);
				}
				Util.arrayCopyNonAtomic(buf, (short) 0, data.do_0102, (short) 0, lc);
				data.do_0102_length = lc;
				JCSystem.commitTransaction();
				break;

			case Constants.TAG_PRIVATE_DO_0103:
				assertUserMode82();
				if ((lc < 0) || (lc > Constants.specialDoMaxLength())) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					return;
				}
				JCSystem.beginTransaction();
				if (data.do_0103_length > 0) {
					Util.arrayFillNonAtomic(data.do_0103, (short) 0, data.do_0103_length, (byte) 0);
				}
				Util.arrayCopyNonAtomic(buf, (short) 0, data.do_0103, (short) 0, lc);
				data.do_0103_length = lc;
				JCSystem.commitTransaction();
				break;

			case Constants.TAG_PRIVATE_DO_0104:
				assertAdmin();
				if ((lc < 0) || (lc > Constants.specialDoMaxLength())) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					return;
				}
				JCSystem.beginTransaction();
				if (data.do_0104_length > 0) {
					Util.arrayFillNonAtomic(data.do_0104, (short) 0, data.do_0104_length, (byte) 0);
				}
				Util.arrayCopyNonAtomic(buf, (short) 0, data.do_0104, (short) 0, lc);
				data.do_0104_length = lc;
				JCSystem.commitTransaction();
				break;

			case Constants.TAG_AES_KEY:
				assertAdmin();
				if ((lc != (short) 16) && (lc != (short) 32)) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					return;
				}
				JCSystem.beginTransaction();
				if (data.aes_key != null) {
					data.aes_key.clearKey();
				}
				data.aes_key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, (short) (lc * 8), false);
				data.aes_key.setKey(buf, (short) 0);
				JCSystem.commitTransaction();
				break;

			case Constants.TAG_CARDHOLDER_CERTIFICATE:
				assertAdmin();
				k = currentTagOccurenceToKey();
				if (k == null) {
					ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
					return;
				}

				apishim.clearCert(currentTagOccurenceToKeyInd());
				if (!apishim.writeCert(currentTagOccurenceToKeyInd(), buf, (short) 0, (short) 0, lc)) {
					ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
				}
				break;

			case Constants.TAG_ALGORITHM_ATTRIBUTES_SIG:
				assertAdmin();
				data.pgp_keys[Persistent.PGP_KEYS_OFFSET_SIG].setAttributes(ec, buf, (short) 0, lc,
						Persistent.PGP_KEYS_OFFSET_SIG, apduBuffer);
				JCSystem.beginTransaction();
				Util.arrayFillNonAtomic(data.digital_signature_counter, (short) 0,
						(byte) data.digital_signature_counter.length, (byte) 0);
				JCSystem.commitTransaction();
				break;

			case Constants.TAG_ALGORITHM_ATTRIBUTES_DEC:
				assertAdmin();
				data.pgp_keys[Persistent.PGP_KEYS_OFFSET_DEC].setAttributes(ec, buf, (short) 0, lc,
						Persistent.PGP_KEYS_OFFSET_DEC, apduBuffer);
				break;

			case Constants.TAG_ALGORITHM_ATTRIBUTES_AUT:
				assertAdmin();
				data.pgp_keys[Persistent.PGP_KEYS_OFFSET_AUT].setAttributes(ec, buf, (short) 0, lc,
						Persistent.PGP_KEYS_OFFSET_AUT, apduBuffer);
				break;

			case Constants.TAG_ALGORITHM_ATTRIBUTES_SM:
				assertAdmin();
				sm.static_key.setAttributes(ec, buf, (short) 0, lc, (byte) 0xFF, apduBuffer);
				break;

			case Constants.TAG_PW_STATUS:
				assertAdmin();
				if (lc != 0x01) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					return;
				}
				if ((buf[0] != 0x00) && (buf[0] != 0x01)) {
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
					return;
				}
				data.user_pin_force_verify_signature = (buf[0] == 0);
				break;

			case Constants.TAG_FINGERPRINT_SIG:
				assertAdmin();
				data.pgp_keys[Persistent.PGP_KEYS_OFFSET_SIG].fingerprint.set(buf, (short) 0, lc);
				break;

			case Constants.TAG_FINGERPRINT_DEC:
				assertAdmin();
				data.pgp_keys[Persistent.PGP_KEYS_OFFSET_DEC].fingerprint.set(buf, (short) 0, lc);
				break;

			case Constants.TAG_FINGERPRINT_AUT:
				assertAdmin();
				data.pgp_keys[Persistent.PGP_KEYS_OFFSET_AUT].fingerprint.set(buf, (short) 0, lc);
				break;

			case Constants.TAG_FINGERPRINT_CA:
				assertAdmin();
				data.fingerprints[Persistent.FINGERPRINTS_OFFSET_CA].set(buf, (short) 0, lc);
				break;

			case Constants.TAG_FINGERPRINT_CB:
				assertAdmin();
				data.fingerprints[Persistent.FINGERPRINTS_OFFSET_CB].set(buf, (short) 0, lc);
				break;

			case Constants.TAG_FINGERPRINT_CC:
				assertAdmin();
				data.fingerprints[Persistent.FINGERPRINTS_OFFSET_CC].set(buf, (short) 0, lc);
				break;

			case Constants.TAG_GENERATION_DATE_SIG:
				// Does nothing as the generation date is dependent on T101 KeyManager
				break;

			case Constants.TAG_GENERATION_DATE_DEC:
				// Does nothing as the generation date is dependent on T101 KeyManager
				break;

			case Constants.TAG_GENERATION_DATE_AUT:
				// Does nothing as the generation date is dependent on T101 KeyManager
				break;

			case Constants.TAG_RESETTING_CODE:
				// Does not rely on checking if admin has been logged in. Requires admin to
				// authenticate again if needed to change default PUK pin.
				transients.setUserPinMode83(false);
				if (ThothPGPApplet.apishim.loginAdminUserAndGetTries(apduBuffer) == (short) -1) {
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
					return;
				}
				transients.setUserPinMode83(true);
				if (!ThothPGPApplet.apishim.pukChangePUKPinPin(apduBuffer)) {
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
					return;
				}

				break;

			case Constants.TAG_KEY_DERIVATION_FUNCTION:
				assertAdmin();
				if ((lc < 0) || (lc > Constants.specialDoMaxLength())) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					return;
				}
				JCSystem.beginTransaction();
				if (data.key_derivation_function_length > 0) {
					Util.arrayFillNonAtomic(data.key_derivation_function, (short) 0,
							data.key_derivation_function_length, (byte) 0);
				}
				Util.arrayCopyNonAtomic(buf, (short) 0, data.key_derivation_function, (short) 0, lc);
				data.key_derivation_function_length = (byte) lc;
				JCSystem.commitTransaction();
				break;

			case Constants.TAG_SECURE_MESSAGING_CERTIFICATE:
				assertAdmin();
				apishim.clearCert((byte) 0xFF);
				if (!apishim.writeCert((byte) 0xFF, buf, (short) 0, (short) 0, lc)) {
					ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
				}

				break;

			default:
				debug[0] = (byte) 0x37;
//				ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
				ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0x37));
				return;
			}
		}
	}

	private final short processGenerateAsymmetricKeyPair(final short lc, final byte p1, final byte p2,
			byte[] apduBuffer) {

		final byte[] buf = transients.buffer;

		if (((p1 != (byte) 0x80) && (p1 != (byte) 0x81)) || (p2 != 0)) {
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			return 0;
		}

		if (lc < 2) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return 0;
		}

		boolean do_reset = false;
		byte pkeyInd = (byte) 0xFF;
		PGPKey pkey;
		byte extended_expect = (byte) 0;

		switch (buf[0]) {
		case Constants.CRT_TAG_SIGNATURE_KEY:
			do_reset = true;
			pkeyInd = Persistent.PGP_KEYS_OFFSET_SIG;
			extended_expect = (byte) 0x01;
			break;

		case Constants.CRT_TAG_DECRYPTION_KEY:
			pkeyInd = Persistent.PGP_KEYS_OFFSET_DEC;
			extended_expect = (byte) 0x02;
			break;

		case Constants.CRT_TAG_AUTHENTICATION_KEY:
			pkeyInd = Persistent.PGP_KEYS_OFFSET_AUT;
			extended_expect = (byte) 0x03;
			break;

		case Constants.CRT_TAG_SECURE_MESSAGING_KEY:
			extended_expect = (byte) 0x04;
			break;

		default:
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return 0;
		}

		if (lc == (short) 2) {
			if (buf[1] != (byte) 0) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				return 0;
			}
		} else if (lc == (short) 5) {
			if ((buf[1] != (byte) 3) || (buf[3] != (byte) 1)) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				return 0;
			}
			if ((buf[2] != (byte) 0x84) || buf[4] != extended_expect) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return 0;
			}
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return 0;
		}

		if (pkeyInd != (byte) 0xFF) {
			pkey = data.pgp_keys[pkeyInd];
		} else {
			pkey = sm.static_key;
		}

		if (p1 == (byte) 0x80) {

			assertAdmin();
			
			pkey.generate(ec, pkeyInd, apishim.defaultExpiryTime, (short) 0, apduBuffer);

			if (do_reset) {
				JCSystem.beginTransaction();
				Util.arrayFillNonAtomic(data.digital_signature_counter, (short) 0,
						(byte) data.digital_signature_counter.length, (byte) 0);
				JCSystem.commitTransaction();
			}
			
		}

		return pkey.getPublicKeyDo(pkeyInd, buf, (short) 0, apduBuffer);
	}

	private final short processPerformSecurityOperation(final short lc, final byte p1, final byte p2,
			byte[] apduBuffer) {

		sensitiveData();

		/* PSO : COMPUTE DIGITAL SIGNATURE */
		if ((p1 == (byte) 0x9e) && (p2 == (byte) 0x9a)) {

			assertUserMode81();

			if (data.user_pin_force_verify_signature) {
				transients.setUserPinMode81(false);
			}

			byte i = 0;
			JCSystem.beginTransaction();
			while (data.digital_signature_counter[(byte) (data.digital_signature_counter.length - i
					- 1)] == (byte) 0xff) {
				++i;
			}
			if (i < data.digital_signature_counter.length) {
				++data.digital_signature_counter[(byte) (data.digital_signature_counter.length - i - 1)];
				if (i > 0) {
					--i;
					Util.arrayFillNonAtomic(data.digital_signature_counter,
							(short) (data.digital_signature_counter.length - i - 1), (byte) (i + 1), (byte) 0);
				}
			}
			JCSystem.commitTransaction();

			return data.pgp_keys[Persistent.PGP_KEYS_OFFSET_SIG].sign(Persistent.PGP_KEYS_OFFSET_SIG, transients.buffer,
					lc, false, apduBuffer);
		}

		/* PSO : DECIPHER */
		if ((p1 == (byte) 0x80) && (p2 == (byte) 0x86)) {

			assertUserMode82();

			if (lc <= 1) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				return 0;
			}

			if (transients.buffer[0] == (byte) 0x02) {

				if (((short) (lc - 1) % Constants.AES_BLOCK_SIZE) != 0) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					return 0;
				}

				if ((data.aes_key == null) || !data.aes_key.isInitialized()) {
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
					return 0;
				}

				cipher_aes_cbc_nopad.init(data.aes_key, Cipher.MODE_DECRYPT);

				final short res = cipher_aes_cbc_nopad.doFinal(transients.buffer, (short) 1, (short) (lc - 1),
						transients.buffer, lc);

				Util.arrayCopyNonAtomic(transients.buffer, lc, transients.buffer, (short) 0, res);

				Util.arrayFillNonAtomic(transients.buffer, lc, res, (byte) 0);

				return res;
			}

			return data.pgp_keys[Persistent.PGP_KEYS_OFFSET_DEC].decipher(Persistent.PGP_KEYS_OFFSET_DEC, ec,
					transients.buffer, lc, apduBuffer);
		}

		/* PSO : ENCIPHER */
		if ((p1 == (byte) 0x86) && (p2 == (byte) 0x80)) {

			assertUserMode82();

			if ((lc <= 0) || ((lc % Constants.AES_BLOCK_SIZE) != 0)) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				return 0;
			}

			if ((data.aes_key == null) || !data.aes_key.isInitialized()) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				return 0;
			}

			cipher_aes_cbc_nopad.init(data.aes_key, Cipher.MODE_ENCRYPT);

			final short res = cipher_aes_cbc_nopad.doFinal(transients.buffer, (short) 0, lc, transients.buffer,
					(short) (lc + 1));

			transients.buffer[lc] = (byte) 0x02;
			Util.arrayCopyNonAtomic(transients.buffer, lc, transients.buffer, (short) 0, (short) (res + 1));

			Util.arrayFillNonAtomic(transients.buffer, (short) (lc + 1), res, (byte) 0);

			return (short) (res + 1);
		}

		ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		return 0;
	}

	private final short processInternalAuthenticate(final short lc, final byte p1, final byte p2, byte[] apduBuffer) {

		if (p2 == (byte) 0x00) {
			switch (p1) {
			case (byte) 0x00:
				sensitiveData();
				assertUserMode82();
				return data.pgp_keys[Persistent.PGP_KEYS_OFFSET_AUT].sign(Persistent.PGP_KEYS_OFFSET_AUT,
						transients.buffer, lc, true, apduBuffer);

			case (byte) 0x01:
				return sm.establish(transients, ec, transients.buffer, lc, apduBuffer);
			}
		}

		ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		return 0;
	}

	private final short processGetChallenge(short le, final byte p1, final byte p2) {
		if ((p1 != (byte) 0) || (p2 != (byte) 0)) {
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			return 0;
		}

		if (le < 0) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return 0;
		}

		if (le > Constants.challengeMaxLength()) {
			le = Constants.challengeMaxLength();
		}

		if (le != 0) {
			random_data.generateData(transients.buffer, (short) 0, le);
		}

		return le;
	}

	private final void processTerminateDf(final byte p1, final byte p2, byte[] apduBuffer) {

		if ((p1 != (byte) 0) || (p2 != (byte) 0)) {
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			return;
		}

		// Bypass admin authentication and use front panel to confirm terminate card to
		// prevent accidental termination
		boolean toTerminate = true;

		try {
			if (!ThothPGPApplet.apishim.confirmationUI(APIShim.TXT_RESET_CARD_TITLE, (short) 0,
					(short) APIShim.TXT_RESET_CARD_TITLE.length, APIShim.TXT_RESET_CARD, (short) 0,
					(short) APIShim.TXT_RESET_CARD.length, apduBuffer)) {
				toTerminate = false;
			}
		} catch (Exception e) {
			// Do nothing and proceed to terminate
		}

		if (toTerminate) {
			data.isTerminated = true;
		}
		return;
	}

	private final void processActivateFile(final byte p1, final byte p2) {
		if (p1 != (byte) 0) {
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			return;
		}

		if (data.isTerminated) {
			switch (p2) {
			case (byte) 0:
				// According to Version 3.3 standards, ACTIVATE_FILE is used to reset ALL KEYS
				// !!!
				sm.reset(false, transients);
				transients.clear();
				data.reset(false);
				break;

			default:
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				return;
			}
		}
	}

	private final void clearConnection() {
		transients.clear();
		sm.clearSession(transients);
	}

	public final void process(final APDU apdu) {
		final byte[] apdubuf = apdu.getBuffer();

		if (apdu.isISOInterindustryCLA() && selectingApplet()) {

			initAPI(apdubuf);
			clearConnection();

			if (data.isTerminated) {
				ISOException.throwIt(Constants.SW_TERMINATED);
			}

			return;
		}

		transients.setSecureMessagingOk(false);

		if (data.isTerminated) {
			if (apdubuf[ISO7816.OFFSET_CLA] != 0) {
				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
				return;
			}

			if (apdubuf[ISO7816.OFFSET_INS] == Constants.INS_ACTIVATE_FILE) {
				processActivateFile(apdubuf[ISO7816.OFFSET_P1], apdubuf[ISO7816.OFFSET_P2]);
				return;
			}

			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			return;
		}

		final byte p1 = apdubuf[ISO7816.OFFSET_P1];
		final byte p2 = apdubuf[ISO7816.OFFSET_P2];

		short available_le = 0;
		short sw = (short) 0x9000;

		// For testing if APIs have been successfully established
		if (apdubuf[ISO7816.OFFSET_CLA] == (byte) 0xB0 && apdubuf[ISO7816.OFFSET_INS] == (byte) 0x00) {			
			short outLen = getKeyGenerationDates(debug, (short) 0, apdubuf);
			
			apdu.setOutgoing();
			apdu.setOutgoingLength(outLen);
			apdu.sendBytesLong(debug, (short) 0, outLen);
			
			return;
		}

		if (((apdubuf[ISO7816.OFFSET_CLA] & Constants.CLA_MASK_CHAINING) != Constants.CLA_MASK_CHAINING)
				&& (apdubuf[ISO7816.OFFSET_INS] == Constants.INS_GET_RESPONSE)) {

			if (transients.chainingInput() || !transients.chainingOutput()) {
				ISOException.throwIt(Constants.SW_CHAINING_ERROR);
				return;
			}

			if ((p1 != 0) || (p2 != 0)) {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				return;
			}

			available_le = transients.outputLength();

		} else if ((apdubuf[ISO7816.OFFSET_CLA] & Constants.CLA_MASK_CHAINING) == Constants.CLA_MASK_CHAINING) {

			prepareChainingInput(apdubuf);
			receiveData(apdu);

		} else {

			prepareChainingInput(apdubuf);
			receiveData(apdu);

			short lc = transients.chainingInputLength();

			if ((apdubuf[ISO7816.OFFSET_CLA]
					& Constants.CLA_MASK_SECURE_MESSAGING) == Constants.CLA_MASK_SECURE_MESSAGING) {
				short off = lc;

				if ((short) (off + 1 + 1 + 1 + 1 + 3) > Constants.INTERNAL_BUFFER_MAX_LENGTH) {
					ISOException.throwIt(Constants.SW_MEMORY_FAILURE);
					return;
				}

				transients.buffer[off++] = apdubuf[ISO7816.OFFSET_CLA];
				transients.buffer[off++] = apdubuf[ISO7816.OFFSET_INS];
				transients.buffer[off++] = p1;
				transients.buffer[off++] = p2;
				if (lc > (short) 0xff) {
					transients.buffer[off++] = (byte) 0;
					transients.buffer[off++] = (byte) ((lc >> 8) & (byte) 0xff);
				}
				transients.buffer[off++] = (byte) (lc & (byte) 0xff);

				transients.setChainingInputLength((short) 0);

				lc = sm.verifyAndDecryptCommand(transients, lc, off);

				transients.setSecureMessagingOk(true);

			} else if (sm.isSessionAvailable()) {
				clearConnection();
			}

			apdu.waitExtension();

			try {

			switch (apdubuf[ISO7816.OFFSET_INS]) {
			case Constants.INS_SELECT_DATA:
				debug[0] = (byte) 0x01;
				processSelectData(lc, p1, p2);
				break;

			case Constants.INS_GET_DATA:
				debug[0] = (byte) 0x02;
				available_le = processGetData(p1, p2, apdubuf);
				break;

			case Constants.INS_GET_NEXT_DATA:
				debug[0] = (byte) 0x03;
				available_le = processGetNextData(p1, p2);
				break;

			case Constants.INS_VERIFY:
				debug[0] = (byte) 0x04;
				processVerify(lc, p1, p2, apdubuf);
				break;

			case Constants.INS_CHANGE_REFERENCE_DATA:
				debug[0] = (byte) 0x05;
				processChangeReferenceData(lc, p1, p2, apdubuf);
				break;

			case Constants.INS_RESET_RETRY_COUNTER:
				debug[0] = (byte) 0x06;
				processResetRetryCounter(lc, p1, p2, apdubuf);
				break;

			case Constants.INS_PUT_DATA_DA:
				debug[0] = (byte) 0x07;
				processPutData(lc, p1, p2, false, apdubuf);
				break;

			case Constants.INS_PUT_DATA_DB:
				debug[0] = (byte) 0x08;
				processPutData(lc, p1, p2, true, apdubuf);
				break;

			case Constants.INS_GENERATE_ASYMMETRIC_KEY_PAIR:
				debug[0] = (byte) 0x09;
				available_le = processGenerateAsymmetricKeyPair(lc, p1, p2, apdubuf);
				break;

			case Constants.INS_PERFORM_SECURITY_OPERATION:
				debug[0] = (byte) 0x0A;
				available_le = processPerformSecurityOperation(lc, p1, p2, apdubuf);
				break;

			case Constants.INS_INTERNAL_AUTHENTICATE:
				debug[0] = (byte) 0x0B;
				available_le = processInternalAuthenticate(lc, p1, p2, apdubuf);
				break;

			case Constants.INS_GET_CHALLENGE:
				debug[0] = (byte) 0x0C;
				available_le = processGetChallenge(apdu.setOutgoing(), p1, p2);
				break;

			case Constants.INS_TERMINATE_DF:
				debug[0] = (byte) 0x0D;
				processTerminateDf(p1, p2, apdubuf);
				break;

			case Constants.INS_ACTIVATE_FILE:
				debug[0] = (byte) 0x0E;
				processActivateFile(p1, p2);
				apishim.initEnv(apdubuf);
				break;

			default:
				debug[0] = (byte) 0x0F;
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
				return;
			}

			} catch (ISOException e) {					
				sw = e.getReason();				
			}

			if (transients.secureMessagingOk()) {

				if (available_le > 0) {
					short tmp = (short) (Constants.AES_BLOCK_SIZE - (available_le % Constants.AES_BLOCK_SIZE));
					available_le = Util.arrayCopyNonAtomic(SecureMessaging.PADDING_BLOCK, (short) 0, transients.buffer,
							available_le, tmp);
				}

				if ((available_le != 0) || (sw == (short) 0x9000) || ((short) (sw & (short) 0x6200) == (short) 0x6200)
						|| ((short) (sw & (short) 0x6300) == (short) 0x6300)) {
					available_le = sm.encryptAndSign(transients, available_le, sw);
				}
			}

			transients.setOutputLength(available_le);
		}

		if (available_le > 0) {

			short resp_le = available_le;

			if (apdu.getCurrentState() != APDU.STATE_OUTGOING) {
				resp_le = apdu.setOutgoing();
				if ((resp_le == (short) 0) || (available_le < resp_le)) {
					resp_le = available_le;
				}
			}

			if (resp_le > (short) 256) {
				resp_le = (short) 256;
			}

			short off = transients.outputStart();

			Util.arrayCopyNonAtomic(transients.buffer, off, apdubuf, (short) 0, resp_le);

			apdu.setOutgoingLength(resp_le);
			apdu.sendBytes((short) 0, resp_le);

			Util.arrayFillNonAtomic(transients.buffer, off, resp_le, (byte) 0);

			available_le -= resp_le;
			off += resp_le;

			if (available_le > 0) {
				transients.setChainingOutput(true);
				transients.setOutputLength(available_le);
				transients.setOutputStart(off);

				if (available_le > (short) 0x00ff) {
					available_le = (short) 0x00ff;
				}

				sw = (short) (ISO7816.SW_BYTES_REMAINING_00 | available_le);

			} else {
				transients.setChainingOutput(false);
				transients.setOutputLength((short) 0);
				transients.setOutputStart((short) 0);
			}
		}
		
		ISOException.throwIt(sw);
	}

	public static void shortToBytes(short s, byte[] b, short offset) {
		b[offset] = (byte) ((s >> 8) & 0xFF);
		b[(short) (offset + 1)] = (byte) (s & 0xFF);
	}

}