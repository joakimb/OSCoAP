package org.eclipse.californium.core.network.stack.objectsecurity;

import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;

import java.net.URISyntaxException;

/**
 * Created by joakim on 2016-03-03.
 */
public interface OSTidDB {

    OSTid getTID(byte[] cid);
    OSTid getTID(String uri)  throws OSTIDException;
    void addTid(byte[] cid, String uri, OSTid tidObj) throws OSTIDException;
}
