package org.eclipse.californium.core.network.stack.objectsecurity;

import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.HashMap;

/**
 * Created by joakim on 2016-03-03.
 */
public class OSCryptoContextDB implements CryptoContextDB {

    static OSCryptoContextDB db;
    HashMap<Cid, CryptoContext> cidMap;
    HashMap<String, CryptoContext> uriMap;

    public static OSCryptoContextDB getDB(){
        if(db == null) db = new OSCryptoContextDB();
        return db;
    }

    public OSCryptoContextDB(){
        uriMap = new HashMap<String, CryptoContext>();
        cidMap = new HashMap<Cid, CryptoContext>();
    }

    @Override
    public CryptoContext getContext(byte[] cid) {
        return cidMap.get(new Cid(cid));
    }
    @Override
    public CryptoContext getContext(String uri) throws OSTIDException {
        uri = normalizeServerUri(uri);
        return uriMap.get(uri);
    }

    private String normalizeServerUri(String uri) throws OSTIDException{
        String normalized = null;
        try{
            normalized = (new URI(uri)).getHost();
        } catch (URISyntaxException e){
            throw new OSTIDException("can not find tid for uri");
        }
        return normalized;
    }

    @Override
    public void addContext(byte[] cid, String uri, CryptoContext tidObj) throws OSTIDException {
        uriMap.put(normalizeServerUri(uri), tidObj);
        cidMap.put(new Cid(cid),tidObj);
    }

    private class Cid {
        private byte[] cid;
        private Cid(byte[] cid){
           this.cid = cid;
        }
        /*private byte[] getBytes(){
            return cid;
        }*/

        @Override
        public int hashCode(){
            MessageDigest md = null;
            try {
                md = MessageDigest.getInstance("MD5");
            } catch (Exception e){
                e.printStackTrace();
            }
            byte[] thedigest;
            return ByteBuffer.wrap(md.digest(cid)).getInt();
        }
        @Override
        public boolean equals(Object o){
            if(!(o instanceof Cid)){
                return false;
            }
            Cid other = (Cid) o;
            if(other.cid.length != this.cid.length){
                return false;
            }
            for (int i = 0; i < cid.length; i++){
                if (this.cid[i] != other.cid[i]){
                    return false;
                }
            }

            return true;
        }
    }
}
