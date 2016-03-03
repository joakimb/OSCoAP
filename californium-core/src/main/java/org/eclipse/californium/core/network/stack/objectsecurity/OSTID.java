package org.eclipse.californium.core.network.stack.objectsecurity;

import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSKeyException;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Created by joakim on 2016-02-23.
 */
public class OSTID {


    private BigInteger cid;  //8 bytes but java lacks support for 8 bit unsigned values
    private int seq;    //3 bytes

    public OSTID(BigInteger cid){
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
        if (!( o instanceof OSTID)) return false;
        OSTID other = (OSTID)o;
        return other.cid.equals(this.cid);
    }

    public byte[] getCid(){
        return cid.toByteArray();
    }

    public int getSeq(){
        return seq;
    }
}
