package org.eclipse.californium.core.network.stack.objectsecurity;

import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;

/**
 * Created by joakim on 2016-02-23.
 */
public class ObjectSecurityOption extends Option{

    private OSCID cid;
    private OSSEQ seq;
    private OSSeqDB seqDB;

    public ObjectSecurityOption(OSCID cid){
        number = OptionNumberRegistry.OBJECT_SECURITY;
        seqDB = new OSHashMapSeqDB();
        this.cid = cid;
        this.seq = seqDB.getSeq(cid);
        if (this.seq == null){
            this.seq = new OSSEQ(0);
        }
    }




}
