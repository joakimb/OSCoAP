package org.eclipse.californium.core.objectsecurity;

import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.objectsecurity.osexcepitons.OSKeyException;

import java.util.Arrays;
import java.util.Map;

/**
 * Created by joakim on 2016-02-23.
 */
public class OSCID {


    private int[] keyId; //2 bytes but java lacks support for 8 bit unsigned values
    private int algId; //1 byte
    private int params; //1byte

    public OSCID(int[] keyId, int algId){
        this.keyId = keyId;
        this.algId = algId;
        this.params = 0;
    }
    public OSCID(int[] keyId, int algId, int params){
        this.keyId = keyId;
        this.algId = algId;
        this.params = params;
    }

    //TODO dummy lookup
    public byte[] getKey() throws OSKeyException{
        byte[] key;
        byte[] key01 = {0,0,0,1};
        byte[] key02 = {0,0,0,2};

        int[] keyId01 = {'0','1'};
        int[] keyId02 = {'0','2'};

        if (Arrays.equals(keyId, keyId01)) key = key01;
        else if (Arrays.equals(keyId, keyId02)) key = key02;
        else throw new OSKeyException("Key ID does not correspond to an actual known key.");
        return key;
    }

    //TODO dummy lookup
    public int getAlg() {
        return OSNumberRegistry.MAC0;
    }

    public int getParams() {
        return params;
    }

    @Override
    public boolean equals(Object o){
        if (!( o instanceof OSCID)) return false;
        OSCID other = (OSCID)o;
        if (this.getAlg() != other.getAlg()) return false;
        if (! Arrays.equals(this.keyId, other.keyId)) return false;
        if (this.getParams() != other.getParams()) return false;
        return true;
    }
}
