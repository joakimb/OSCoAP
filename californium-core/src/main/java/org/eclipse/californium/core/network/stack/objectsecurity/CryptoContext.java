package org.eclipse.californium.core.network.stack.objectsecurity;

import COSE.AlgorithmID;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSSequenceNumberException;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Created by joakim on 2016-02-23.
 */
public class CryptoContext {


    //TODO, BigInteger encodes to 2-complement in .toByteArray(), should not be a problem, but test it
    private BigInteger cid;  //8 bytes but java lacks support for 8 bit unsigned values
    private BigInteger senderSeq;    //1-8 bytes, contains the last used value
    private BigInteger receiverSeq;    //1-8 bytes, contains the last used value (max 56 bits?)
    private BigInteger seqMax;         //2^56 - 1
    private byte[] senderSalt = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    private byte[] receiverSalt = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
    private int replayProtectionWin = 0;
    private byte[] senderKey = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    private byte[] receiverKey = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};


    public CryptoContext(BigInteger cid){
        this.cid = cid;
        //this.senderSeq = new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        //this.receiverSeq = new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        this.senderSeq = BigInteger.ZERO;
        this.receiverSeq = BigInteger.ZERO;
        seqMax = new BigInteger("2").pow(56).subtract(BigInteger.ONE);
    }

    public byte[] getSenderIV(){
        byte seq[] = getSenderSeq();
        byte salt[] = Arrays.copyOf(senderSalt, 7);
        return ivSeqXOR(seq,salt);
    }

    private byte[] ivSeqXOR(byte[] seq, byte[]salt){
        byte iv[] = new byte[7];
        int seqOffset = iv.length - seq.length;
        System.arraycopy(seq, 0, iv, seqOffset, seq.length);

        for (int i = 0; i < iv.length; i++) {

            iv[i] = (byte) (((int) iv[i]) ^ ((int) salt[i]));
        }
        return iv;
    }

    public byte[] getReceiverIV(byte[] seq){
        byte salt[] = Arrays.copyOf(receiverSalt, 7);
        return ivSeqXOR(seq, salt);
    }

    public byte[] getSenderKey(){
        return senderKey;
    }

    public byte[] getReceiverKey(){
        return receiverKey;
    }

    public AlgorithmID getAlg() {
        return AlgorithmID.AES_CCM_64_64_128;
    }
    
    public byte[] getCid(){
        return cid.toByteArray();
    }

    public byte[] getSenderSeq(){

        byte[] array = senderSeq.toByteArray();
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

    public void increaseSenderSeq() throws OSSequenceNumberException {
        if (senderSeq.compareTo(seqMax) >= 0){
            throw new OSSequenceNumberException("sequence number too big");
        }
        senderSeq = senderSeq.add(BigInteger.ONE);
    }

    public void increaseReceiverSeq() throws OSTIDException {
        if (receiverSeq.compareTo(seqMax) >= 0){
            throw new OSTIDException("sequence number too big");
        }
        receiverSeq = receiverSeq.add(BigInteger.ONE);
    }

    public byte[] getReceiverSeq(){
        byte[] array = receiverSeq.toByteArray();
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



    public void setSeqMax(BigInteger seqMax){
        this.seqMax = seqMax;
    }

    @Override
    public boolean equals(Object o){
        if (!( o instanceof CryptoContext)) return false;
        CryptoContext other = (CryptoContext)o;
        return other.cid.equals(this.cid);
    }

    public void checkIncomingSeq(byte[] seq) throws OSSequenceNumberException{
        if (!Arrays.equals(seq, getReceiverSeq())) { //TODO, handle messages arriving out of order
            throw new OSSequenceNumberException("unexpected sequence number, expected: " + new BigInteger(getReceiverSeq()).toString() + " got: " + new BigInteger(seq).toString());
        }
    }
}
