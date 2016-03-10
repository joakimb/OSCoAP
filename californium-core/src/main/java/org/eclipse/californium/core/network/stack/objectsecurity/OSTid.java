package org.eclipse.californium.core.network.stack.objectsecurity;

import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSKeyException;

import java.math.BigInteger;

/**
 * Created by joakim on 2016-02-23.
 */
public class OSTid {


    private BigInteger cid;  //8 bytes but java lacks support for 8 bit unsigned values
    private BigInteger senderSeq;    //1-8 bytes
    private BigInteger receiverSeq;    //1-8 bytes
    private BigInteger senderSalt;
    private BigInteger receiverSalt;
    private int replayProtectionWin = 0;
    private byte[] keySender = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    private byte[] keyReceiver = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};

    public OSTid(BigInteger cid){
        this.cid = cid;
        this.senderSeq = BigInteger.ZERO;
        this.receiverSeq = BigInteger.ZERO;
    }

    public byte[] getSenderKey() throws OSKeyException{
        return keySender;
    }

    public byte[] getReceiverKey(){
        return keyReceiver;
    }

    public int getAlg() {
        return OSNumberRegistry.MAC0;
    }

    public byte[] getCid(){
        return cid.toByteArray();
    }

    public BigInteger getSenderSeq(){
        return senderSeq;
    }

    public BigInteger getReceiverSeq(){
        return receiverSeq;
    }

    public BigInteger getSenderSalt() {
        return senderSalt;
    }

    public BigInteger getReceiverSalt() {
        return receiverSalt;
    }

    @Override
    public boolean equals(Object o){
        if (!( o instanceof OSTid)) return false;
        OSTid other = (OSTid)o;
        return other.cid.equals(this.cid);
    }

}
