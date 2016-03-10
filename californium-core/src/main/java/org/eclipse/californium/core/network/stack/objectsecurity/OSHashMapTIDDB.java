package org.eclipse.californium.core.network.stack.objectsecurity;

import java.util.HashMap;

/**
 * Created by joakim on 2016-03-03.
 */
public class OSHashMapTIDDB implements OSTidDB {

    static OSHashMapTIDDB db;
    HashMap<String, OSTid> map;

    public static OSHashMapTIDDB getDB(){
        if(db == null) db = new OSHashMapTIDDB();
        return db;
    }

    public OSHashMapTIDDB(){
        map = new HashMap<String, OSTid>();
    }

    @Override
    public OSTid getTID(String uri) {
        return map.get(uri);
    }

    @Override
    public void addTid(String uri, OSTid tidObj) {
        map.put(uri,tidObj);
    }
}
