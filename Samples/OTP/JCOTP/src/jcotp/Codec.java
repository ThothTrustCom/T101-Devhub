package jcotp;

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

	public static void intToBytes(byte[] b, short offset, int i) {
		b[offset] = (byte) ((i >> 24) & 0xFF);
		b[(short) (offset + 1)] = (byte) ((i >> 16) & 0xFF);
		b[(short) (offset + 2)] = (byte) ((i >> 8) & 0xFF);
		b[(short) (offset + 3)] = (byte) (i & 0xFF);
	}
}