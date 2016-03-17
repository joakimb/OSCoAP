package org.eclipse.californium.core.network.stack.objectsecurity;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.HashMap;

/**
 * Created by joakim on 2016-03-03.
 */
public class OSHashMapTIDDB implements OSTidDB {

    static OSHashMapTIDDB db;
    HashMap<Cid, OSTid> map;

    public static OSHashMapTIDDB getDB(){
        if(db == null) db = new OSHashMapTIDDB();
        return db;
    }

    public OSHashMapTIDDB(){
        map = new HashMap<Cid, OSTid>();
    }

    @Override
    public OSTid getTID(byte[] cid) {
        return map.get(new Cid(cid));
    }

    @Override
    public void addTid(byte[] cid, OSTid tidObj) {
        map.put(new Cid(cid),tidObj);
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
