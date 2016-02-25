package org.eclipse.californium.core.network.stack.objectsecurity;

/**
 * Created by joakim on 2016-02-25.
 */
public interface OSSeqDB {

    OSSEQ getSeq(OSCID cid);
    void setSeq(OSCID cid, OSSEQ seq);

}
