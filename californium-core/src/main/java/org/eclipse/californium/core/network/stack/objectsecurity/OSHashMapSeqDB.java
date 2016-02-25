package org.eclipse.californium.core.network.stack.objectsecurity;

import java.util.HashMap;

/**
 * Created by joakim on 2016-02-25.
 */
public class OSHashMapSeqDB implements OSSeqDB{


    static OSHashMapSeqDB db;
    HashMap<OSCID,OSSEQ> map;

    public OSHashMapSeqDB getDB(){
        if(db == null) db = new OSHashMapSeqDB();
        return db;
    }

    public OSHashMapSeqDB(){
        map = new HashMap<OSCID,OSSEQ>();
    }

    @Override
    public OSSEQ getSeq(OSCID cid) {
        return map.get(cid);
    }

    @Override
    public void setSeq(OSCID cid, OSSEQ seq) {
        map.put(cid,seq);
    }
}
