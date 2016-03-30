package org.eclipse.californium.core.network.stack.objectsecurity;

import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;

import java.net.URISyntaxException;

/**
 * Created by joakim on 2016-03-03.
 */
public interface OSTidDB {

    OSTid getClientTID(byte[] cid);
    OSTid getClientTID(String uri)  throws OSTIDException;
    void addClientTid(byte[] cid, String uri, OSTid tidObj) throws OSTIDException;
}
