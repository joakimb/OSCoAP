package org.eclipse.californium.core.network.stack.objectsecurity;

import java.math.BigInteger;
import java.util.HashMap;

/**
 * Created by joakim on 2016-03-03.
 */
public class OSHashMapTIDDB implements OSTransactionIDDB {

    static OSHashMapTIDDB db;
    HashMap<BigInteger, OSTID> map;

    public static OSHashMapTIDDB getDB(){
        if(db == null) db = new OSHashMapTIDDB();
        return db;
    }

    public OSHashMapTIDDB(){
        map = new HashMap<BigInteger, OSTID>();
    }

    @Override
    public OSTID getTID(BigInteger tid) {
        return map.get(tid);
    }

    @Override
    public void setTID(BigInteger tid, OSTID tidObj) {
        map.put(tid,tidObj);
    }
}
