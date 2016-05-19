package org.eclipse.californium.core.network.stack.objectsecurity.Encryption;

import COSE.Attribute;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;
import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.network.stack.objectsecurity.CryptoContext;
import org.eclipse.californium.core.network.stack.objectsecurity.OSSerializer;
import org.eclipse.californium.core.network.stack.objectsecurity.OptionJuggle;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSSequenceNumberException;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;

/**
 * Created by joakim on 06/04/16.
 */
public abstract class Encryptor {
    CryptoContext tid;
    OptionSet options;
    byte[] confidential;
    byte[] aad;

    protected byte[] encryptAndEncode(Encrypt0Message enc, CryptoContext tid) throws CoseException, OSSequenceNumberException {

        try {
            byte[] key = tid.getSenderKey();
            //enc.addAttribute(HeaderKeys.PARTIAL_IV, CBORObject.FromObject(tid.getSenderSeq()),Attribute.ProtectedAttributes);
            enc.addAttribute(HeaderKeys.IV, CBORObject.FromObject(tid.getSenderIV()),Attribute.DontSendAttributes);
            enc.addAttribute(HeaderKeys.Algorithm, tid.getAlg().AsCBOR(), Attribute.DontSendAttributes);
            enc.encrypt(key);
            System.out.println("IV: " + bytesToHex(tid.getSenderIV()));
            System.out.println("KEY: " + bytesToHex(key));
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            System.exit(0);
        }
        return enc.EncodeToBytes();
    }

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

    protected void collectData(Message message){
        options = message.getOptions();
        confidential = OSSerializer.serializeConfidentialData(options, message.getPayload());
        aad = serializeAAD();
        System.out.println("confidential: " + bytesToHex(confidential));
    }

    protected void setOSPayload(byte[] protectedPayload, Message message) {

        Option osOpt = OptionJuggle.filterOSOption(options);
        if (message.getPayloadSize() > 0) {
            System.out.println("in payload");
            osOpt.setValue(new byte[0]);
            message.setPayload(protectedPayload);
        } else {
            System.out.println("in option");
            osOpt.setValue(protectedPayload);
            message.setPayload(new byte[0]);
        }
        message.setOptions(OptionJuggle.clearOptionsPresentInOSPayload(options, osOpt));
    }

    protected void checkTid() throws OSTIDException{
        if (tid == null) {
            System.out.print("TID NOT PRESENT, ABORTING");
            System.exit(1);
            //TODO change behaviour to ignore OS or throw Exception earlier i chain, e.g. in CoapClient.java
        }
    }

    protected abstract byte[] serializeAAD();
}


