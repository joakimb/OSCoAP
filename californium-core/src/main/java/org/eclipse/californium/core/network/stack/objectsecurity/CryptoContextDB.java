package org.eclipse.californium.core.network.stack.objectsecurity;

import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;

/**
 * Created by joakim on 2016-03-03.
 */
public interface CryptoContextDB {

    CryptoContext getContext(byte[] cid);
    CryptoContext getContext(String uri)  throws OSTIDException;
    void addContext(byte[] cid, String uri, CryptoContext tidObj) throws OSTIDException;
}
