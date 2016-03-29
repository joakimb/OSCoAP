package org.eclipse.californium.core.network.stack.objectsecurity;

import COSE.AlgorithmID;
import com.upokecenter.cbor.CBORObject;

import java.math.BigInteger;

/**
 * Created by joakim on 2016-02-23.
 */
public class OSTid {


    //TODO, BigInteger encodes to 2-complement in .toByteArray(), should not be a problem, but test it
    private BigInteger cid;  //8 bytes but java lacks support for 8 bit unsigned values
    private BigInteger clientSeq;    //1-8 bytes, contains the next unused value
    private BigInteger serverSeq;    //1-8 bytes, contains the next unused value
    private BigInteger clientSalt;
    private BigInteger serverSalt;
    private int replayProtectionWin = 0;
    private byte[] clientKey = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    private byte[] serverKey = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    public OSTid(BigInteger cid){
        this.cid = cid;
        //this.clientSeq = new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        //this.serverSeq = new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        this.clientSeq = BigInteger.ZERO;
        this.serverSeq = BigInteger.ZERO;
    }

    public byte[] getSenderKey(){
        return clientKey;
    }

    public byte[] getReceiverKey(){
        return serverKey;
    }

    public CBORObject getAlg() {
        return AlgorithmID.AES_CCM_16_64_128.AsCBOR();
    }
    
    public byte[] getCid(){
        return cid.toByteArray();
    }

    public byte[] getClientSeq(){
        byte[] array = clientSeq.toByteArray();
        /*
        //remove leading zeroes
        int numLeadingZeroes = 0;
        while (numLeadingZeroes < array.length && array[numLeadingZeroes] != 0){
            numLeadingZeroes++;
        }
        byte[] newArr = new byte[array.length - numLeadingZeroes];
        System.arraycopy(array, numLeadingZeroes, newArr, 0, newArr.length);

        return newArr;
        */ return array;
    }

    public void increaseSenderSeq(){
        //clientSeq = clientSeq.add(BigInteger.ONE);
    }

    public void increaseReceiverSeq(){
        //gitreceiverSeq = serverSeq.add(BigInteger.ONE);
    }

    public byte[] getServerSeq(){
        byte[] array = serverSeq.toByteArray();
/*
        //remove leading zeroes
        int numLeadingZeroes = 0;
        while (numLeadingZeroes < array.length && array[numLeadingZeroes] != 0){
            numLeadingZeroes++;
        }
        byte[] newArr = new byte[array.length - numLeadingZeroes];
        System.arraycopy(array, numLeadingZeroes, newArr, 0, newArr.length);

        return newArr;
        */return array;
    }

    public BigInteger getClientSalt() {
        return clientSalt;
    }

    public BigInteger getServerSalt() {
        return serverSalt;
    }

    @Override
    public boolean equals(Object o){
        if (!( o instanceof OSTid)) return false;
        OSTid other = (OSTid)o;
        return other.cid.equals(this.cid);
    }

}
