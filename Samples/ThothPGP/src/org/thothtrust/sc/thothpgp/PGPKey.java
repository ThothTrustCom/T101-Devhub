/**
 * BSD-3-Clause
 * 
 * Copyright 2020 ThothTrust Pte Ltd.
 * 
 * Refer to LICENSE file for full license text.
 */
package org.thothtrust.sc.thothpgp;

import KM101.T101OpenAPI;
import javacard.framework.*;

public class PGPKey {

	public Fingerprint fingerprint = null;
	public byte[] attributes = null;
	public byte attributes_length = 0;
	public boolean is_secure_messaging_key = false;
	public boolean has_been_generated = false;
	public static boolean is_initialized = false;
	private byte[] tempBuf = null;

	/**
	 * Only call once during creation of PGPKey object in Persistent data store.
	 *
	 * @param for_secure_messaging
	 */
	public PGPKey(byte ind, boolean for_secure_messaging) {

		is_secure_messaging_key = for_secure_messaging;

		if (!is_secure_messaging_key) {
			fingerprint = new Fingerprint();
		}

		attributes = new byte[Constants.ALGORITHM_ATTRIBUTES_MAX_LENGTH];

		reset(ind, true);
	}

	private void resetKeys(byte ind, boolean isRegistering, byte[] apduBuffer) {
		if (is_initialized) {
			ThothPGPApplet.apishim.destroyObject(ThothPGPApplet.apishim.getKeyHandle(ind), (short) 0, (short) 4,
					apduBuffer);
		}

		ThothPGPApplet.apishim.clearCert(ind);

		if (!is_secure_messaging_key) {
			fingerprint.reset(isRegistering);
		}

		has_been_generated = false;
		is_initialized = false;
	}

	/**
	 * 
	 * 
	 * @param isRegistering
	 * @param keyHandle
	 * @param offset
	 * @param len
	 * @param username
	 * @param nameOff
	 * @param nameLen
	 */
	protected void reset(byte ind, boolean isRegistering, byte[] apduBuffer) {
		resetKeys(ind, isRegistering, apduBuffer);

		Common.beginTransaction(isRegistering);
		if (attributes_length > 0) {
			Util.arrayFillNonAtomic(attributes, (short) 0, attributes_length, (byte) 0);
			attributes_length = (byte) 0;
		}

		if (is_secure_messaging_key) {
			Util.arrayCopyNonAtomic(Constants.ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING, (short) 0, attributes,
					(short) 0, (short) Constants.ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING.length);
			attributes_length = (byte) Constants.ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING.length;
		} else {
			Util.arrayCopyNonAtomic(Constants.ALGORITHM_ATTRIBUTES_DEFAULT, (short) 0, attributes, (short) 0,
					(short) Constants.ALGORITHM_ATTRIBUTES_DEFAULT.length);
			attributes_length = (byte) Constants.ALGORITHM_ATTRIBUTES_DEFAULT.length;
		}
		Common.commitTransaction(isRegistering);
	}

	/**
	 * Use for container destruction activity. Does not delete keys from T101
	 * KeyManager because the entire container will be destroyed.
	 * 
	 * @param isRegistering
	 */
	protected void reset(byte ind, boolean isRegistering) {
		if (ThothPGPApplet.apishim != null) {
			ThothPGPApplet.apishim.clearCert(ind);
		}

		if (!is_secure_messaging_key) {
			fingerprint.reset(isRegistering);
		}

		has_been_generated = false;
		is_initialized = false;

		Common.beginTransaction(isRegistering);
		if (attributes_length > 0) {
			Util.arrayFillNonAtomic(attributes, (short) 0, attributes_length, (byte) 0);
			attributes_length = (byte) 0;
		}

		if (is_secure_messaging_key) {
			Util.arrayCopyNonAtomic(Constants.ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING, (short) 0, attributes,
					(short) 0, (short) Constants.ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING.length);
			attributes_length = (byte) Constants.ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING.length;
		} else {
			Util.arrayCopyNonAtomic(Constants.ALGORITHM_ATTRIBUTES_DEFAULT, (short) 0, attributes, (short) 0,
					(short) Constants.ALGORITHM_ATTRIBUTES_DEFAULT.length);
			attributes_length = (byte) Constants.ALGORITHM_ATTRIBUTES_DEFAULT.length;
		}
		Common.commitTransaction(isRegistering);
	}

	protected byte keyInformation() {
		byte res = (byte) 0x0;
		if (is_initialized) {
			if (has_been_generated) {
				res = (byte) 0x01;
			} else {
				res = (byte) 0x02;
			}
		}
		return res;
	}

	protected void setCertificate(byte ind, byte[] buf, short off, short len) {
		if ((len < 0) || (len > Constants.cardholderCertificateMaxLength())) {

			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return;
		}
		ThothPGPApplet.apishim.clearCert(ind);
		ThothPGPApplet.apishim.writeCert(ind, buf, off, (short) 0, len);
	}

	protected void setAttributes(ECCurves ec, byte[] buf, short off, short len, byte ind, byte[] apduBuffer) {
		if ((len < Constants.ALGORITHM_ATTRIBUTES_MIN_LENGTH) || (len > Constants.ALGORITHM_ATTRIBUTES_MAX_LENGTH)) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return;
		}

		switch (buf[off]) {
		case 0x01:
			if ((len != 6) || is_secure_messaging_key) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}
			if ((Util.getShort(buf, (short) (off + 1)) < 2048) || (Util.getShort(buf, (short) (off + 3)) != 0x11)
					|| (buf[(short) (off + 5)] < 0) || (buf[(short) (off + 5)] > 3)) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}
			break;

		case 0x12:
		case 0x13:
			if (len < 2) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}
			byte delta = (buf[(short) (len - 1)] == (byte) 0xff) ? (byte) 1 : (byte) 0;
			ECParams params = ec.findByOid(buf, (short) (off + 1), (byte) (len - 1 - delta));
			if (params == null) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}
			if ((buf[0] != 0x12) && is_secure_messaging_key) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				return;
			}
			break;

		default:
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			return;
		}

		resetKeys(ind, false, apduBuffer);

		JCSystem.beginTransaction();
		if (attributes_length > 0) {
			Util.arrayFillNonAtomic(attributes, (short) 0, attributes_length, (byte) 0);
		}
		Util.arrayCopyNonAtomic(buf, off, attributes, (short) 0, len);
		attributes_length = (byte) len;
		JCSystem.commitTransaction();
	}

	protected boolean isRsa() {
		return (attributes[0] == 1);
	}

	protected short rsaModulusBitSize() {
		return Util.getShort(attributes, (short) 1);
	}

	protected short rsaExponentBitSize() {
		return Util.getShort(attributes, (short) 3);
	}

	protected boolean isEc() {
		return ((attributes[0] == (byte) 0x12) || (attributes[0] == (byte) 0x13));
	}

	protected ECParams ecParams(ECCurves ec) {
		byte delta = (attributes[(short) (attributes_length - 1)] == (byte) 0xff) ? (byte) 1 : (byte) 0;
		return ec.findByOid(attributes, (short) 1, (byte) (attributes_length - 1 - delta));
	}

	private boolean generateRSA(byte ind, byte[] expiryTS, short expTSOff, byte[] apduBuffer) {
		return ThothPGPApplet.apishim.newAsymmetricKeyObject(T101OpenAPI.KEY_TYPE_RSA, ind, expiryTS, expTSOff,
				apduBuffer);
	}

	private byte getECKeyType(ECCurves ec) {
		short bits = ecParams(ec).nb_bits;
		if (bits == (short) 256) {
			return T101OpenAPI.KEY_TYPE_ECC_P256R1;
		} else if (bits == (short) 384) {
			return T101OpenAPI.KEY_TYPE_ECC_P384R1;
		} else if (bits == (short) 521) {
			return T101OpenAPI.KEY_TYPE_ECC_P521R1;
		}
		return T101OpenAPI.KEY_TYPE_ECC_P256R1;
	}

	private boolean generateEC(ECCurves ec, byte ind, byte[] expiryTS, short expTSOff, byte[] apduBuffer) {
		return ThothPGPApplet.apishim.newAsymmetricKeyObject(getECKeyType(ec), ind, expiryTS, expTSOff, apduBuffer);
	}

	protected void generate(ECCurves ec, byte ind, byte[] expiryTS, short expTSOff, byte[] apduBuffer) {
		boolean generated = false;

		resetKeys(ind, false, apduBuffer);

		if (isRsa()) {
			generated = generateRSA(ind, expiryTS, expTSOff, apduBuffer);
		} else if (isEc()) {
			generated = generateEC(ec, ind, expiryTS, expTSOff, apduBuffer);
		}

		if (generated) {
			has_been_generated = true;
			is_initialized = true;
		} else {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
	}

	protected short getPublicKeyDo(byte ind, byte[] buf, short off, byte[] apduBuffer) {

		if (!is_initialized) {
			ThothPGPApplet.debug[0] = (byte) 0x21;
			ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
			return 0;
		}

		off = Util.setShort(buf, off, (short) 0x7f49);

		short publen = ThothPGPApplet.apishim.getPublicKey(ThothPGPApplet.apishim.getKeyHandle(ind), (short) 0,
				(short) 4, apduBuffer);

		if (publen == (short) -1) {
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		}

		if (isRsa()) {

			short modulus_size = Common.bitsToBytes(rsaModulusBitSize());
			short exponent_size = Common.bitsToBytes(rsaExponentBitSize());

			short mlensize = (short) ((modulus_size > (short) 0xff) ? 3 : 2);

			short flen = (short) (1 + mlensize + modulus_size + 1 + 1 + exponent_size);

			off = Common.writeLength(buf, off, flen);

			buf[off++] = (byte) 0x81;
			off = Common.writeLength(buf, off, modulus_size);
			Util.arrayCopyNonAtomic(apduBuffer, (short) 0, buf, off, publen);
			off += publen;

			buf[off++] = (byte) 0x82;
			off = Common.writeLength(buf, off, exponent_size);
			Util.arrayCopyNonAtomic(Constants.RSA_EXPONENT, (short) 0, buf, off, (short) Constants.RSA_EXPONENT.length);
			off += (short) Constants.RSA_EXPONENT.length;

			return off;

		} else if (isEc()) {

			short qsize = (short) (1 + 2 * (short) ((publen / 8) + (((publen % 8) == 0) ? 0 : 1)));
			short rsize = (short) (1 + qsize);

			if (qsize > 0x7f) {
				rsize = (short) (rsize + 2);
			} else {
				rsize = (short) (rsize + 1);
			}

			off = Common.writeLength(buf, off, rsize);

			buf[off++] = (byte) 0x86;

			off = Common.writeLength(buf, off, qsize);

			Util.arrayCopyNonAtomic(apduBuffer, (short) 0, buf, off, publen);
			off += publen;

			return off;

		}

		ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		return off;
	}

	protected short sign(byte ind, byte[] buf, short lc, boolean forAuth, byte[] apduBuffer) {

		if (!is_initialized) {
			ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
			return 0;
		}

		short off = 0;

		byte[] sha_header = null;

		if (isRsa()) {

			if (!forAuth) {
				if (lc == (short) (2 + Constants.DSI_SHA256_HEADER[1])) {
					sha_header = Constants.DSI_SHA256_HEADER;
				} else if (lc == (short) (2 + Constants.DSI_SHA384_HEADER[1])) {
					sha_header = Constants.DSI_SHA384_HEADER;
				} else if (lc == (short) (2 + Constants.DSI_SHA512_HEADER[1])) {
					sha_header = Constants.DSI_SHA512_HEADER;
				} else {
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
					return 0;
				}

				if (Util.arrayCompare(buf, (short) 0, sha_header, (short) 0, (byte) sha_header.length) != 0) {
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
					return 0;
				}
			}

			if (lc > (short) (((short) (Common.bitsToBytes(rsaModulusBitSize()) * 2)) / 5)) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				return 0;
			}

			// Append PKCS #1 v1.5 header padding first
			short padSize = (short) (256 - 3 - lc);
			tempBuf = null;
			tempBuf = new byte[(short) 256];
			tempBuf[1] = (byte) 0x01;
			Util.arrayFillNonAtomic(tempBuf, (short) 2, padSize, (byte) 0xFF);
			Util.arrayCopyNonAtomic(buf, (short) 0, tempBuf, (short) (3 + padSize), lc);

			// Sign raw over PKCS1 formatted data
			off = ThothPGPApplet.apishim.signRSA(ind, tempBuf, (short) 0, (short) tempBuf.length, buf, (short) 0,
					apduBuffer);

			tempBuf = null;

			if (off == (short) -1) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}

			return off;

		} else if (isEc()) {
			short sig_size = ThothPGPApplet.apishim.signPreComputeHashECDSA(ind, buf, (short) 0, lc, apduBuffer);

			if (off == (short) -1) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}

			Util.arrayCopyNonAtomic(apduBuffer, (short) 0, buf, lc, sig_size);

			off = (short) (lc + 1);
			if ((buf[off] & (byte) 0x80) != (byte) 0) {
				++off;
			}
			++off;

			if ((buf[off++] != (byte) 0x02)) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return 0;
			}

			if ((buf[off] & (byte) 0x80) != (byte) 0) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return 0;
			}

			short r_size = Util.makeShort((byte) 0, buf[off++]);
			short r_off = off;

			off += r_size;

			if ((buf[off++] != (byte) 0x02)) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return 0;
			}

			if ((buf[off] & (byte) 0x80) != (byte) 0) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return 0;
			}

			short s_size = Util.makeShort((byte) 0, buf[off++]);
			short s_off = off;

			off = (short) (lc + sig_size);

			if (r_size < s_size) {
				off = Util.arrayFillNonAtomic(buf, off, (short) (s_size - r_size), (byte) 0);
			}

			off = Util.arrayCopyNonAtomic(buf, r_off, buf, off, r_size);

			if (s_size < r_size) {
				off = Util.arrayFillNonAtomic(buf, off, (short) (r_size - s_size), (byte) 0);
			}

			off = Util.arrayCopyNonAtomic(buf, s_off, buf, off, s_size);

			off = Util.arrayCopyNonAtomic(buf, (short) (lc + sig_size), buf, (short) 0, (short) (off - lc - sig_size));

			Util.arrayFillNonAtomic(buf, off, (short) (lc + sig_size - off), (byte) 0);

			return off;
		}

		ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		return 0;
	}

	protected short decipher(byte ind, ECCurves ec, byte[] buf, short lc, byte[] apduBuffer) {

		if (!is_initialized) {
			ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
			return 0;
		}

		short off = 0;

		if (isRsa()) {
			short modulus_size = Common.bitsToBytes(rsaModulusBitSize());

			if (lc != (short) (modulus_size + 1)) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				return 0;
			}

			if (buf[0] != (byte) 0) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return 0;
			}
			
			short len = ThothPGPApplet.apishim.decryptRSA(ind, buf, (short) 1, (short) (lc - 1), buf, lc, apduBuffer);

			if (len == (short) -1) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}

			off = Util.arrayCopyNonAtomic(buf, lc, buf, (short) 0, len);

			Util.arrayFillNonAtomic(buf, lc, len, (byte) 0);

			return off;

		} else if (isEc()) {

			ECParams params = ecParams(ec);
			short elc = 7;

			if (params.nb_bits >= (short) 512) {
				elc = 10;
			}

			if (lc != (short) (elc + 1 + (short) (2 * Common.bitsToBytes(params.nb_bits)))) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return 0;
			}

			if (buf[off] != (byte) 0xA6) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return 0;
			}
			++off;

			elc = Common.readLength(buf, off, (short) (lc - off));
			off = Common.skipLength(buf, off, (short) (lc - off));
			if (elc != (short) (lc - off)) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				return 0;
			}

			if (Util.getShort(buf, off) != (short) (0x7f49)) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return 0;
			}
			off += 2;

			elc = Common.readLength(buf, off, (short) (lc - off));
			off = Common.skipLength(buf, off, (short) (lc - off));
			if (elc != (short) (lc - off)) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				return 0;
			}

			if (buf[off] != (byte) 0x86) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return 0;
			}
			++off;

			elc = Common.readLength(buf, off, (short) (lc - off));
			off = Common.skipLength(buf, off, (short) (lc - off));
			if (elc != (short) (lc - off)) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				return 0;
			}

			// Perform ECDH
			short len = ThothPGPApplet.apishim.ecdh(ind, buf, off, (short) (lc - off), apduBuffer);

			if (len <= (short) 0) {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}

			off = Util.arrayCopyNonAtomic(apduBuffer, (short) 0, buf, (short) 0, len);
			Util.arrayFillNonAtomic(apduBuffer, (short) 0, len, (byte) 0x00);

			return off;
		}

		ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		return 0;
	}

}