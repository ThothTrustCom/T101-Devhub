package thetapass;

import javacard.framework.ISOException;
import javacard.framework.Util;

public class Codec {
	public static final byte[] BCD_SIZE_PER_BYTES = { 0, 3, 5, 8, 10, 13, 15, 17, 20, 22, 25, 27, 29, 32, 34, 37, 39,
			41, 44, 46, 49, 51, 53, 56, 58, 61, 63, 66, 68, 70, 73, 75, 78 };

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

	public static void intToBytes(int i, byte[] b, short offset) {
		b[offset] = (byte) ((i >> 24) & 0xFF);
		b[(short) (offset + 1)] = (byte) ((i >> 16) & 0xFF);
		b[(short) (offset + 2)] = (byte) ((i >> 8) & 0xFF);
		b[(short) (offset + 3)] = (byte) (i & 0xFF);
	}

	public static int bytesToInt(byte b1, byte b2, byte b3, byte b4) {
		return (int) (((b1 & 0xFF) << 24) | ((b2 & 0xFF) << 16) | ((b3 & 0xFF) << 8) | ((b4 & 0xFF) << 0));
	}

	public static void shortToBytes(short s, byte[] b, short offset) {
		b[offset] = (byte) ((s >> 8) & 0xFF);
		b[(short) (offset + 1)] = (byte) (s & 0xFF);
	}

	public static short bytesToShort(byte b1, byte b2) {
		return (short) (((b1 & 0xFF) << 8) | ((b2 & 0xFF) << 0));
	}

	public static boolean isInputAllowable(byte[] bArray, short off, short len, boolean allowSymbol) {
		for (short i = off; i < len; i++) {
			byte b = bArray[i];
			if (allowSymbol) {
				if (b < 32 || b > 126) {
					ISOException.throwIt(Util.makeShort((byte) 0x6f, b));
					return false;
				}
			} else {
				if (!((b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122))) {
					ISOException.throwIt(Util.makeShort((byte) 0x6a, b));
					return false;
				}
			}
		}
		return true;
	}
}