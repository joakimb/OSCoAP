package org.eclipse.californium.core.network.stack.objectsecurity;

/**
 * Created by joakim on 2016-03-03.
 */
public interface OSTransactionIDDB {

    OSTID getTID(byte[] tid);
    void setTID(byte[] tid, OSTID tidObj);
}
