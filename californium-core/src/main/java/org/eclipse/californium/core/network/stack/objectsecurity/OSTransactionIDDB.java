package org.eclipse.californium.core.network.stack.objectsecurity;

import java.math.BigInteger;

/**
 * Created by joakim on 2016-03-03.
 */
public interface OSTransactionIDDB {

    OSTID getTID(BigInteger tid);
    void setTID(BigInteger tid, OSTID tidObj);
}
