package org.eclipse.californium.core.objectsecurity;

import com.upokecenter.cbor.CBORObject;

import java.util.Map;

/**
 * Created by joakim on 2016-02-23.
 */
public class OSCID {


    private char[] keyId;
    private char[] algId;
    private Map params;

    public OSCID(char[] keyId, char[] algId){
        this.keyId = keyId;
        this.algId = algId;
        this.params = null;
    }
    public OSCID(char[] keyId, char[] algId, Map params){
        this.keyId = keyId;
        this.algId = algId;
        this.params = params;
    }

    public char[] getKeyId() {
        return keyId;
    }

    public char[] getAlgId() {
        return algId;
    }

    public Map getParams() {
        return params;
    }

}
