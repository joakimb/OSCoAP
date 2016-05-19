package org.eclipse.californium.core.network.stack.objectsecurity.Encryption;

import COSE.Attribute;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;
import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.network.stack.objectsecurity.CryptoContext;
import org.eclipse.californium.core.network.stack.objectsecurity.OptionJuggle;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSException;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSSequenceNumberException;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Created by joakim on 06/04/16.
 */
public abstract class Decryptor {

    byte[] protectedData;

    protected byte[] decryptAndDecode(Encrypt0Message enc) throws OSSequenceNumberException, OSTIDException, OSException {


        byte[] seq = {0x00};//(enc.findAttribute(HeaderKeys.PARTIAL_IV)).GetByteString();
        CryptoContext tid = getTid();

        byte[] result = null;

        try {
            byte[] key = tid.getReceiverKey();
            tid.increaseReceiverSeq();
            tid.checkIncomingSeq(seq);
            checkTid(tid);
            enc.setExternal(serializeAAD(tid));
            enc.addAttribute(HeaderKeys.Algorithm, tid.getAlg().AsCBOR(), Attribute.DontSendAttributes);
            enc.addAttribute(HeaderKeys.IV, CBORObject.FromObject(getTid().getReceiverIV(seq)),Attribute.DontSendAttributes);
            result = enc.decrypt(key);
        } catch (CoseException e) {
            e.printStackTrace();
            System.exit(1);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            System.exit(1);
        }
        return result;

    }

    protected void collectData(Message message){
        Option op = OptionJuggle.filterOSOption(message.getOptions());
        protectedData = op.getLength() == 0 ? message.getPayload() : op.getValue();
    }

    public Encrypt0Message prepareCOSEStructure(){
        Encrypt0Message enc = new Encrypt0Message();
        try {
            System.out.println("PROTECTED: "  + bytesToHex(protectedData));
            enc.DecodeFromCBORObject(CBORObject.DecodeFromBytes(protectedData));
        } catch (CoseException e) {
            e.printStackTrace();
        }
        return enc;
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
    protected void checkTid(CryptoContext tid) throws OSTIDException {
        if (tid == null) {
            System.out.print("TID NOT PRESENT, ABORTING");
            System.exit(1);
            //TODO change behaviour to ignore OS or throw Exception earlier i chain, e.g. in CoapClient.java
        }
    }

    protected abstract byte[] serializeAAD(CryptoContext tid);
    protected abstract CryptoContext getTid() throws OSException;
}
