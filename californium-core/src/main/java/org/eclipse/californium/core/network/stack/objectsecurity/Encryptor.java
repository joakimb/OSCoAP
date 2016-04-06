package org.eclipse.californium.core.network.stack.objectsecurity;

import COSE.Attribute;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;
import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;

/**
 * Created by joakim on 06/04/16.
 */
public abstract class Encryptor {
    OSTid tid;
    OptionSet options;
    byte[] confidential;
    byte[] aad;

    protected byte[] encryptAndEncode(Encrypt0Message enc, OSTid tid) throws CoseException {
        enc.addAttribute(HeaderKeys.PARTIAL_IV, CBORObject.FromObject(tid.getSenderSeq()),Attribute.ProtectedAttributes);
        enc.addAttribute(HeaderKeys.Algorithm, tid.getAlg().AsCBOR(), Attribute.DontSendAttributes);//TODO vad skiljer fr[n setExternal()
        try {
            byte[] key = tid.getSenderKey();
            tid.increaseSenderSeq();
            enc.encrypt(key);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }
        return enc.EncodeToBytes();
    }

    protected void collectData(Message message){
        options = message.getOptions();
        confidential = OSSerializer.serializeConfidentialData(options, message.getPayload());
        aad = serializeAAD();
    }

    protected void setOSPayload(byte[] protectedPayload, Message message) {

        ObjectSecurityOption osOpt = (ObjectSecurityOption) OptionJuggle.filterOSOption(options);
        if (message.getPayloadSize() > 0) {
            osOpt.setValue(new byte[0]);
            message.setPayload(protectedPayload);
        } else {
            osOpt.setValue(protectedPayload);
            message.setPayload(new byte[0]);
        }
        message.setOptions(OptionJuggle.moveOptionsToOSPayload(options, osOpt));
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


