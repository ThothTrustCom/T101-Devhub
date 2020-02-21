/**
 * BSD-3-Clause
 * 
 * Copyright 2020 ThothTrust Pte Ltd.
 * 
 * Refer to LICENSE file for full license text.
 */
package org.thothtrust.sc.thothpgp;

import javacard.framework.*;
import javacard.security.*;


public final class ECParams {

    protected final short nb_bits;
    protected final byte[] oid;
    protected final byte[] field, a, b, g, r;
    protected final short k;

    protected ECParams(final short nb_bits,
                       final byte[] oid,
                       final byte[] field, /* p */
                       final byte[] a,
                       final byte[] b,
                       final byte[] g,
                       final byte[] r, /* n */
                       final short k) /* h */ {
        this.nb_bits = nb_bits;
        this.oid = oid;
        this.field = field;
        this.a = a;
        this.b = b;
        this.g = g;
        this.r = r;
        this.k = k;
    }


    protected final boolean matchOid(final byte[] buf, final short off, final short len) {
        return (len == (short)oid.length) && (Util.arrayCompare(buf, off, oid, (short)0, len) == 0);
    }

    protected final void setParams(final ECKey key) {
        key.setFieldFP(field, (short)0, (short)field.length);
        key.setA(a, (short)0, (short)a.length);
        key.setB(b, (short)0, (short)b.length);
        key.setG(g, (short)0, (short)g.length);
        key.setR(r, (short)0, (short)r.length);
        key.setK(k);
    }
}