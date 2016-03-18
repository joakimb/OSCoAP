package org.eclipse.californium.core.network.stack.objectsecurity;

import COSE.*;
import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.coap.*;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.network.serialization.DatagramReader;
import org.eclipse.californium.core.network.serialization.DatagramWriter;
import org.eclipse.californium.core.network.stack.objectsecurity.OSTid;

import java.util.List;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.*;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.CODE_BITS;

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

    public void encryptAndEncode(byte[] confidential, byte[] aad, OSTid tid){
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
        //add encypted msg to payload
        try {
            value = enc.EncodeToBytes();
        } catch (CoseException e) {
            e.printStackTrace();
        }
    }

    public byte[] decryptAndDecode(byte[] payload, int code){

        Encrypt0Message enc = new Encrypt0Message();
        try {
            enc.DecodeFromCBORObject(CBORObject.DecodeFromBytes(payload));
        } catch (CoseException e) {
            e.printStackTrace();
        }
        byte[] cid = (enc.findAttribute(HeaderKeys.KID)).GetByteString();
        OSTid tid = OSHashMapTIDDB.getDB().getTID(cid);

        byte[] aad = OSSerializer.serializeAdditionalAuthenticatedData(code, tid);
        enc.setExternal(aad);
        enc.addAttribute(HeaderKeys.Algorithm, tid.getAlg(), Attribute.DontSendAttributes);

        if (tid == null) {
            //throw new OSTIDException("No Context for URI.");
            System.out.print("TID NOT FOUND ABORTING");
            System.exit(1);
            //TODO change behaviour to ignore OS or throw Exception earlier i chain,
        }
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

        return result;

    }


}

