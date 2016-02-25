package org.eclipse.californium.core.objectsecurity;

/**
 * Created by joakim on 2016-02-25.
 */
public interface OSSeqDB {

    OSSEQ getSeq(OSCID cid);
    void setSeq(OSCID cid, OSSEQ seq);

}
