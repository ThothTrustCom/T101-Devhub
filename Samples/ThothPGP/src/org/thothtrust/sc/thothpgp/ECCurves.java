/**
 * BSD-3-Clause
 * 
 * Copyright 2020 ThothTrust Pte Ltd.
 * 
 * Refer to LICENSE file for full license text.
 */
package org.thothtrust.sc.thothpgp;

public final class ECCurves {

	protected final ECParams[] curves;

	protected ECCurves() {
		final ECParams ansix9p256r1 = new ECParams((short) 256, ECConstants.ansix9p256r1_oid);

		final ECParams ansix9p384r1 = new ECParams((short) 384, ECConstants.ansix9p384r1_oid);

		final ECParams ansix9p521r1 = new ECParams((short) 521, ECConstants.ansix9p521r1_oid);

		curves = new ECParams[] { ansix9p256r1, ansix9p384r1, ansix9p521r1 };
	}

	protected final ECParams findByOid(final byte[] buf, final short off, final byte len) {
		byte i = 0;
		while (i < curves.length) {
			if (curves[i].matchOid(buf, off, len)) {
				return curves[i];
			}
			++i;
		}

		return null;
	}
}