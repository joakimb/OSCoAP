package org.eclipse.californium.core.network.stack.objectsecurity;

import java.util.HashMap;

/**
 * Created by joakim on 2016-03-03.
 */
public class OSHashMapTIDDB implements OSTransactionIDDB {

    static OSHashMapTIDDB db;
    HashMap<byte[], OSTID> map;

    public static OSHashMapTIDDB getDB(){
        if(db == null) db = new OSHashMapTIDDB();
        return db;
    }

    public OSHashMapTIDDB(){
        map = new HashMap<byte[], OSTID>();
    }

    @Override
    public OSTID getTID(byte[] tid) {
        return map.get(tid);
    }

    @Override
    public void setTID(byte[] tid, OSTID tidObj) {
        map.put(tid,tidObj);
    }
}
