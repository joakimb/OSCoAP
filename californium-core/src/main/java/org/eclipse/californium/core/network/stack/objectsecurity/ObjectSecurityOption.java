package org.eclipse.californium.core.network.stack.objectsecurity;

import COSE.*;
import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.coap.*;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSSequenceNumberException;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Created by joakim on 2016-02-23.
 */
public class ObjectSecurityOption extends Option {

    public ObjectSecurityOption(){
        number = OptionNumberRegistry.OBJECT_SECURITY;
    }

    public ObjectSecurityOption(Option option){
        this();
        this.value = option.getValue();
    }



    public static byte[] extractSeqFromProtected(byte[] protectedData){
        Encrypt0Message enc = new Encrypt0Message();
        try {
            enc.DecodeFromCBORObject(CBORObject.DecodeFromBytes(protectedData));
        } catch (CoseException e) {
            e.printStackTrace();
        }
        byte[] seq = (enc.findAttribute(HeaderKeys.PARTIAL_IV)).GetByteString();
        return seq;
    }


    public byte[] decryptAndDecodeResponse(byte[] payload, byte[] aad, OSTid tid) throws OSSequenceNumberException{
        Encrypt0Message enc = new Encrypt0Message();
        try {
            enc.DecodeFromCBORObject(CBORObject.DecodeFromBytes(payload));
        } catch (CoseException e) {
            e.printStackTrace();
        }
        return decryptAndDecode(enc, tid, payload, aad);
    }

    private byte[] decryptAndDecode(Encrypt0Message enc, OSTid tid, byte[] payload, byte[] aad) throws OSSequenceNumberException{

        System.out.println("desr: " + bytesToHex(payload));

        byte[] seq = (enc.findAttribute(HeaderKeys.PARTIAL_IV)).GetByteString();

        System.out.println("seq1: " + bytesToHex(seq));
        System.out.println("seq2: " + bytesToHex(tid.getReceiverSeq()));
        enc.setExternal(aad);
        enc.addAttribute(HeaderKeys.Algorithm, tid.getAlg().AsCBOR(), Attribute.DontSendAttributes);

        if (tid == null) {
            //throw new OSTIDException("No Context for URI.");
            System.out.print("TID NOT FOUND ABORTING");
            System.exit(1);
            //TODO change behaviour to ignore OS or throw Exception earlier i chain,
        }
        if(!Arrays.equals(seq,tid.getReceiverSeq())){ //TODO, handle messages arriving out of order
            throw new OSSequenceNumberException("unexpected sequence number, expected: " + new BigInteger(tid.getReceiverSeq()).toString() + " got: " + new BigInteger(seq).toString());
        }
        System.out.println("receiving sequenceno: " + new BigInteger(seq).toString() + "/" + new BigInteger(tid.getReceiverSeq()));
        byte[] result = null;

        try {
            byte[] key = tid.getReceiverKey();
            tid.increaseReceiverSeq();
            result = enc.decrypt(key);
        } catch (CoseException e) {
            e.printStackTrace();
            System.exit(1);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }
        return result;

    }

    //TODO remove development method:
    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}

