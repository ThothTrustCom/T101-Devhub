package bpecc;

import javacard.framework.*;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;

public class BPECC extends Applet {

	protected static byte[] A = { (byte) 0x7D, (byte) 0x5A, (byte) 0x09, (byte) 0x75, (byte) 0xFC, (byte) 0x2C,
			(byte) 0x30, (byte) 0x57, (byte) 0xEE, (byte) 0xF6, (byte) 0x75, (byte) 0x30, (byte) 0x41, (byte) 0x7A,
			(byte) 0xFF, (byte) 0xE7, (byte) 0xFB, (byte) 0x80, (byte) 0x55, (byte) 0xC1, (byte) 0x26, (byte) 0xDC,
			(byte) 0x5C, (byte) 0x6C, (byte) 0xE9, (byte) 0x4A, (byte) 0x4B, (byte) 0x44, (byte) 0xF3, (byte) 0x30,
			(byte) 0xB5, (byte) 0xD9 };
	protected static byte[] B = { (byte) 0x26, (byte) 0xDC, (byte) 0x5C, (byte) 0x6C, (byte) 0xE9, (byte) 0x4A,
			(byte) 0x4B, (byte) 0x44, (byte) 0xF3, (byte) 0x30, (byte) 0xB5, (byte) 0xD9, (byte) 0xBB, (byte) 0xD7,
			(byte) 0x7C, (byte) 0xBF, (byte) 0x95, (byte) 0x84, (byte) 0x16, (byte) 0x29, (byte) 0x5C, (byte) 0xF7,
			(byte) 0xE1, (byte) 0xCE, (byte) 0x6B, (byte) 0xCC, (byte) 0xDC, (byte) 0x18, (byte) 0xFF, (byte) 0x8C,
			(byte) 0x07, (byte) 0xB6 };
	protected static byte[] G = { (byte) 0x04, (byte) 0x8B, (byte) 0xD2, (byte) 0xAE, (byte) 0xB9, (byte) 0xCB,
			(byte) 0x7E, (byte) 0x57, (byte) 0xCB, (byte) 0x2C, (byte) 0x4B, (byte) 0x48, (byte) 0x2F, (byte) 0xFC,
			(byte) 0x81, (byte) 0xB7, (byte) 0xAF, (byte) 0xB9, (byte) 0xDE, (byte) 0x27, (byte) 0xE1, (byte) 0xE3,
			(byte) 0xBD, (byte) 0x23, (byte) 0xC2, (byte) 0x3A, (byte) 0x44, (byte) 0x53, (byte) 0xBD, (byte) 0x9A,
			(byte) 0xCE, (byte) 0x32, (byte) 0x62, (byte) 0x54, (byte) 0x7E, (byte) 0xF8, (byte) 0x35, (byte) 0xC3,
			(byte) 0xDA, (byte) 0xC4, (byte) 0xFD, (byte) 0x97, (byte) 0xF8, (byte) 0x46, (byte) 0x1A, (byte) 0x14,
			(byte) 0x61, (byte) 0x1D, (byte) 0xC9, (byte) 0xC2, (byte) 0x77, (byte) 0x45, (byte) 0x13, (byte) 0x2D,
			(byte) 0xED, (byte) 0x8E, (byte) 0x54, (byte) 0x5C, (byte) 0x1D, (byte) 0x54, (byte) 0xC7, (byte) 0x2F,
			(byte) 0x04, (byte) 0x69, (byte) 0x97 };
	protected static byte[] R = { (byte) 0xA9, (byte) 0xFB, (byte) 0x57, (byte) 0xDB, (byte) 0xA1, (byte) 0xEE,
			(byte) 0xA9, (byte) 0xBC, (byte) 0x3E, (byte) 0x66, (byte) 0x0A, (byte) 0x90, (byte) 0x9D, (byte) 0x83,
			(byte) 0x8D, (byte) 0x71, (byte) 0x8C, (byte) 0x39, (byte) 0x7A, (byte) 0xA3, (byte) 0xB5, (byte) 0x61,
			(byte) 0xA6, (byte) 0xF7, (byte) 0x90, (byte) 0x1E, (byte) 0x0E, (byte) 0x82, (byte) 0x97, (byte) 0x48,
			(byte) 0x56, (byte) 0xA7 };
	protected static byte[] FP = { (byte) 0xA9, (byte) 0xFB, (byte) 0x57, (byte) 0xDB, (byte) 0xA1, (byte) 0xEE,
			(byte) 0xA9, (byte) 0xBC, (byte) 0x3E, (byte) 0x66, (byte) 0x0A, (byte) 0x90, (byte) 0x9D, (byte) 0x83,
			(byte) 0x8D, (byte) 0x72, (byte) 0x6E, (byte) 0x3B, (byte) 0xF6, (byte) 0x23, (byte) 0xD5, (byte) 0x26,
			(byte) 0x20, (byte) 0x28, (byte) 0x20, (byte) 0x13, (byte) 0x48, (byte) 0x1D, (byte) 0x1F, (byte) 0x6E,
			(byte) 0x53, (byte) 0x77 };

	static final byte K = (byte) 0x01;

	static final short KEY_SIZE = 256;

	private KeyPair kp;
	private ECPrivateKey privKey;
	private ECPublicKey pubKey;
	private Signature ecdsaSigner;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new BPECC();
	}

	protected BPECC() {
		privKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
		pubKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
		setCurveParameters(privKey);
		setCurveParameters(pubKey);
		kp = new KeyPair(pubKey, privKey);
		kp.genKeyPair();
		ecdsaSigner = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
		register();
	}

	public void process(APDU apdu) {
		if (selectingApplet()) {
			return;
		}

		byte[] buffer = apdu.getBuffer();
		byte ins = buffer[ISO7816.OFFSET_INS];
		short len = 0;

		switch (ins) {
		case (byte) 0x00:
			// Check key statuses
			if (privKey != null && pubKey != null) {
				if (privKey.isInitialized() && pubKey.isInitialized()) {
					ISOException.throwIt(ISO7816.SW_NO_ERROR);
				} else {
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				}
			} else {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
			break;
		case (byte) 0x01:
			// Get public key
			len = pubKey.getW(buffer, (short) 0);
			apdu.setOutgoingAndSend((short) 0, len);
			break;
		case (byte) 0x02:
			// Get private key
			len = privKey.getS(buffer, (short) 0);
			apdu.setOutgoingAndSend((short) 0, len);
			break;
		case (byte) 0x03:
			// Sign message
			len = apdu.setIncomingAndReceive();
			ecdsaSigner.init(privKey, Signature.MODE_SIGN);
			len = ecdsaSigner.sign(buffer, apdu.getOffsetCdata(), len, buffer, apdu.getOffsetCdata());
			apdu.setOutgoingAndSend(apdu.getOffsetCdata(), len);
			break;
		case (byte) 0x04:
			// Load your own keypair
			len = apdu.setIncomingAndReceive();
			if (len != 97) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			privKey.clearKey();
			pubKey.clearKey();
			setCurveParameters(privKey);
			setCurveParameters(pubKey);
			try {
				privKey.setS(buffer, apdu.getOffsetCdata(), (short) 32);
			} catch (Exception e) {
				ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0x01));
			}
			try {
				pubKey.setW(buffer, (short) (apdu.getOffsetCdata() + 32), (short) 65);
			} catch (Exception e) {
				ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0x02));
			}
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			break;
		}

	}

	public void setCurveParameters(ECKey key) {
		key.setA(A, (short) 0x00, (short) A.length);
		key.setB(B, (short) 0x00, (short) B.length);
		key.setFieldFP(FP, (short) 0x00, (short) FP.length);
		key.setG(G, (short) 0x00, (short) G.length);
		key.setR(R, (short) 0x00, (short) R.length);
		key.setK(K);
	}
}
