/*
 * RFC4226 compliant HMAC-OTP Engine.
 * Can only handle 6 digits OTP numbers.
 */
package jcotp;

import javacard.framework.Util;
import javacard.security.MessageDigest;

public class HOTPEngine {

	public static short generateOTP(MessageDigest hash, byte[] key, short keyOff, short keyLen, byte[] ctr,
			short ctrOff, short ctrLen, byte[] buff, short buffOff, byte[] output, short outOff) {
		short macLen = 0;
		int binary = 0;
		short rtLen = 0;

		// Compute HMAC hash
		macLen = HMACSHA.process(hash, key, keyOff, keyLen, ctr, ctrOff, ctrLen, buff, buffOff, buff,
				(short) (buffOff + 64), buff, (short) (buffOff + 128), buff, (short) (buffOff + 192));
		
		// Copy to front of buffer for easier access
		Util.arrayCopyNonAtomic(buff, (short) (buffOff + 192), buff, buffOff, macLen);

		// Convert to integer for maths
		short offset = (short) (buff[(short) (macLen - 1 + buffOff)] & 0xf);
		
		binary = ((buff[(short) (offset + buffOff)] & 0x7f) << 24)
				| ((buff[(short) (offset + buffOff + 1)] & 0xff) << 16)
				| ((buff[(short) (offset + buffOff + 2)] & 0xff) << 8) 
				| (buff[(short) (offset + buffOff + 3)] & 0xff);

		// 6 digit OTP code modulus math
		Codec.intToBytes(buff, buffOff, binary % 1000000);

		// Convert back to bytes
		rtLen = Codec.toDecimalASCII(buff, buffOff, (short) 4, output, outOff);
		return rtLen;
	}
}