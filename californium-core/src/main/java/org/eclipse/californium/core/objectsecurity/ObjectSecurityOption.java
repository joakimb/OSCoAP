package org.eclipse.californium.core.objectsecurity;

import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;

/**
 * Created by joakim on 2016-02-23.
 */
public class ObjectSecurityOption extends Option{

    private OSCID cid;
    private byte[] sequenceNumber;

    public ObjectSecurityOption(OSCID cid){
        number = OptionNumberRegistry.OBJECT_SECURITY;
        this.cid = cid;
        this.sequenceNumber = null;
    }

}
