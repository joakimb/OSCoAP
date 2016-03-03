package org.eclipse.californium.core.network.stack.objectsecurity;

import org.eclipse.californium.core.network.serialization.DatagramWriter;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSKeyException;

import java.util.Arrays;

/**
 * Created by joakim on 2016-02-23.
 */
public class OSCID {


    private byte[] cid;  //3 bytes but java lacks support for 8 bit unsigned values

    public OSCID(byte[] cid){
        this.cid = cid;
    }

    //TODO dummy lookup
    public byte[] getKey() throws OSKeyException{
        byte[] key;
        byte[] key01 = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        byte[] key02 = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2};

        int keyId01 = 1;
        int keyId02 = 2;

        //if (keyId == keyId01) key = key01;
        //else if (keyId == keyId02) key = key02;
        //else throw new OSKeyException("Key ID does not correspond to an actual known key.");
        key = key02; //TODO change
        return key;
    }

    //TODO dummy lookup
    public int getAlg() {
        return OSNumberRegistry.MAC0;
    }


    @Override
    public boolean equals(Object o){
        if (!( o instanceof OSCID)) return false;
        OSCID other = (OSCID)o;
        return Arrays.equals(this.cid, other.cid);
    }

    public byte[] getCid(){
        return cid;
    }
}
