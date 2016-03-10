package org.eclipse.californium.core.network.stack.objectsecurity;

/**
 * Created by joakim on 2016-03-03.
 */
public interface OSTidDB {

    OSTid getTID(String uri);
    void addTid(String uri, OSTid tidObj);
}
