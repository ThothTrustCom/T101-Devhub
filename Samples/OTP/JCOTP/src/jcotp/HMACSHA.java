package jcotp;

import javacard.framework.Util;
import javacard.security.MessageDigest;

/**
 * HMAC Class. Supports any supported HMAC-SHA1 and HMAC-SHA2 classes that the
 * card supports.
 */
public class HMACSHA {

	private static final byte IPAD = (byte) 0x36;
	private static final byte OPAD = (byte) 0x5c;
	private static short outSize = 20;
	private static short blockSize = 64;
	public static short HMAC_SHA256_OUT_SIZE = (short) 32;
	public static short HMAC_SHA384_OUT_SIZE = (short) 48;
	public static short HMAC_SHA512_OUT_SIZE = (short) 64;
	public static short HMAC_SHA256_BLOCK_SIZE = (short) 64;
	public static short HMAC_SHA384_BLOCK_SIZE = (short) 128;
	public static short HMAC_SHA512_BLOCK_SIZE = (short) 128;

	/**
	 * HMAC algo from RFC-2104. Setup the blocksize of the algo. Default SHA-1.
	 *
	 * @param hash
	 * @param hKey
	 */
	public static short process(MessageDigest hash, byte[] hKey, short hKeyOff, short hKeyLen, byte[] msg, short mOff,
			short mLen, byte[] ipad, short offIPad, byte[] opad, short offOPad, byte[] secB, short offSecB, byte[] oMsg,
			short outOff) {
		if (hash.getAlgorithm() == MessageDigest.ALG_SHA) {
			outSize = (short) 20; // SHA-1
			blockSize = 64;
		} else if (hash.getAlgorithm() == MessageDigest.ALG_SHA_256) {
			outSize = (short) 32; // SHA-256
			blockSize = 64;
		} else if (hash.getAlgorithm() == MessageDigest.ALG_SHA_384) {
			outSize = (short) 48; // SHA-384
			blockSize = (short) 128;
		} else if (hash.getAlgorithm() == MessageDigest.ALG_SHA_512) {
			outSize = (short) 64; // SHA-512
			blockSize = (short) 128;
		} else {
			return (short) -1;
		}

		Util.arrayFillNonAtomic(ipad, offIPad, blockSize, (byte) 0x00);
		Util.arrayFillNonAtomic(opad, offOPad, blockSize, (byte) 0x00);
		Util.arrayFillNonAtomic(secB, offSecB, blockSize, (byte) 0x00);

		// Block size == key size. Adjust key.
		if (hKeyLen > blockSize) {
			hash.reset();
			hash.doFinal(hKey, hKeyOff, hKeyLen, secB, offSecB);
		} else {
			Util.arrayCopyNonAtomic(hKey, hKeyOff, secB, offSecB, hKeyLen);
		}

		// Setup IPAD & OPAD secrets while using first byte of the outMsg array via
		// outOffset
		for (short s = (short) 0; s < blockSize; s++) {
			ipad[(short) (s + offIPad)] = (byte) (secB[(short) (s + offSecB)] ^ IPAD);
			opad[(short) (s + offOPad)] = (byte) (secB[(short) (s + offSecB)] ^ OPAD);
		}

		// hash(i_key_pad | message)
		hash.reset();
		hash.update(ipad, offIPad, blockSize);
		hash.doFinal(msg, mOff, mLen, oMsg, outOff);

		// hash(o_key_pad | i_pad-hashed)
		hash.reset();
		hash.update(opad, offOPad, blockSize);
		return hash.doFinal(oMsg, outOff, outSize, oMsg, outOff);
	}

	public static short getBlockSize(byte hashAlgo) {
		switch (hashAlgo) {
		case MessageDigest.ALG_SHA_256:
			return HMAC_SHA256_BLOCK_SIZE;
		case MessageDigest.ALG_SHA_384:
			return HMAC_SHA384_BLOCK_SIZE;
		case MessageDigest.ALG_SHA_512:
			return HMAC_SHA512_BLOCK_SIZE;
		default:
			return (short) -1;
		}
	}
}