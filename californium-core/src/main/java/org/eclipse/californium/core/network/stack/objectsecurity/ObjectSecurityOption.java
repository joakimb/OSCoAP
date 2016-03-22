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

    /*
    private Message message;
    private int code;


    public ObjectSecurityOption(Request message){

        this(message,message.getCode() == null ? 0 : message.getCode().value);

    }

    public ObjectSecurityOption(Response message){

        this(message,message.getCode() == null ? 0 : message.getCode().value);

    }

    private ObjectSecurityOption(Message message, int code){
        number = OptionNumberRegistry.OBJECT_SECURITY;
        this.message = message;
        this.code = code;
    }
*/

    public ObjectSecurityOption(){
        number = OptionNumberRegistry.OBJECT_SECURITY;
    }

    public ObjectSecurityOption(Option option){
        this();
        this.value = option.getValue();
    }

    public byte[] encryptAndEncode(byte[] confidential, byte[] aad, OSTid tid) throws CoseException {
        Encrypt0Message enc = new Encrypt0Message();

        enc.SetContent(confidential);
        enc.setExternal(aad);
        enc.addAttribute(HeaderKeys.Algorithm, tid.getAlg(), Attribute.DontSendAttributes);//TODO vad skiljer fr[n setExternal()
        enc.addAttribute(HeaderKeys.KID, CBORObject.FromObject(tid.getCid()),Attribute.ProtectedAttributes);
        enc.addAttribute(HeaderKeys.PARTIAL_IV, CBORObject.FromObject(tid.getSenderSeq()),Attribute.ProtectedAttributes);
        try {

            byte[] key = tid.getSenderKey();
            enc.encrypt(key);
        } catch (CoseException e){
            e.printStackTrace();
            System.exit(1);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }
        tid.increaseSenderSeq();
        return enc.EncodeToBytes();
    }

    public byte[] decryptAndDecode(byte[] payload, int code) throws OSSequenceNumberException{

        System.out.println("desr: " + bytesToHex(payload));
        Encrypt0Message enc = new Encrypt0Message();
        try {
            enc.DecodeFromCBORObject(CBORObject.DecodeFromBytes(payload));
        } catch (CoseException e) {
            e.printStackTrace();
        }
        byte[] cid = (enc.findAttribute(HeaderKeys.KID)).GetByteString();
        byte[] seq = (enc.findAttribute(HeaderKeys.PARTIAL_IV)).GetByteString();
        OSTid tid = OSHashMapTIDDB.getDB().getTID(cid);

        System.out.println("seq1: " + bytesToHex(seq));
        System.out.println("seq2: " + bytesToHex(tid.getReceiverSeq()));
        byte[] aad = OSSerializer.serializeAdditionalAuthenticatedData(code, tid);
        enc.setExternal(aad);
        enc.addAttribute(HeaderKeys.Algorithm, tid.getAlg(), Attribute.DontSendAttributes);

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
            result = enc.decrypt(key);
        } catch (CoseException e) {
            e.printStackTrace();
            System.exit(1);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }
        tid.increaseReceiverSeq();
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

