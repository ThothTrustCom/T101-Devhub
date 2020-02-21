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
        final ECParams ansix9p256r1 =
            new ECParams((short)256,
                         ECConstants.ansix9p256r1_oid,
                         ECConstants.ansix9p256r1_field,
                         ECConstants.ansix9p256r1_a,
                         ECConstants.ansix9p256r1_b,
                         ECConstants.ansix9p256r1_g,
                         ECConstants.ansix9p256r1_r,
                         (short)1);

        final ECParams ansix9p384r1 =
            new ECParams((short)384,
                         ECConstants.ansix9p384r1_oid,
                         ECConstants.ansix9p384r1_field,
                         ECConstants.ansix9p384r1_a,
                         ECConstants.ansix9p384r1_b,
                         ECConstants.ansix9p384r1_g,
                         ECConstants.ansix9p384r1_r,
                         (short)1);

        final ECParams ansix9p521r1 =
            new ECParams((short)521,
                         ECConstants.ansix9p521r1_oid,
                         ECConstants.ansix9p521r1_field,
                         ECConstants.ansix9p521r1_a,
                         ECConstants.ansix9p521r1_b,
                         ECConstants.ansix9p521r1_g,
                         ECConstants.ansix9p521r1_r,
                         (short)1);

        final ECParams brainpoolP256r1 =
            new ECParams((short)256,
                         ECConstants.brainpoolP256r1_oid,
                         ECConstants.brainpoolP256r1_field,
                         ECConstants.brainpoolP256r1_a,
                         ECConstants.brainpoolP256r1_b,
                         ECConstants.brainpoolP256r1_g,
                         ECConstants.brainpoolP256r1_r,
                         (short)1);

        final ECParams brainpoolP384r1 =
            new ECParams((short)384,
                         ECConstants.brainpoolP384r1_oid,
                         ECConstants.brainpoolP384r1_field,
                         ECConstants.brainpoolP384r1_a,
                         ECConstants.brainpoolP384r1_b,
                         ECConstants.brainpoolP384r1_g,
                         ECConstants.brainpoolP384r1_r,
                         (short)1);

        final ECParams brainpoolP512r1 =
            new ECParams((short)512,
                         ECConstants.brainpoolP512r1_oid,
                         ECConstants.brainpoolP512r1_field,
                         ECConstants.brainpoolP512r1_a,
                         ECConstants.brainpoolP512r1_b,
                         ECConstants.brainpoolP512r1_g,
                         ECConstants.brainpoolP512r1_r,
                         (short)1);

        curves = new ECParams[]{
            ansix9p256r1,
            ansix9p384r1,
            ansix9p521r1,
            brainpoolP256r1,
            brainpoolP384r1,
            brainpoolP512r1
        };
    }

    protected final ECParams findByOid(final byte[] buf,
                                       final short off,
                                       final byte len) {
        byte i = 0;
        while(i < curves.length) {
            if(curves[i].matchOid(buf, off, len)) {
                return curves[i];
            }
            ++i;
        }

        return null;
    }
}