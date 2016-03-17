package org.eclipse.californium.core.network.stack.objectsecurity;

/**
 * Created by joakim on 2016-03-03.
 */
public interface OSTidDB {

    OSTid getTID(byte[] cid);
    void addTid(byte[] cid, OSTid tidObj);
}
