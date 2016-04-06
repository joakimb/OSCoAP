package org.eclipse.californium.core.network.stack.objectsecurity;

import COSE.Attribute;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;
import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;

/**
 * Created by joakim on 06/04/16.
 */
public class RequestEncryptor extends Encryptor {

    Request request;

    public RequestEncryptor(OSTid tid, Request request){
        this.tid = tid;
        this.request = request;
    }

    public Request encrypt() throws OSTIDException{

        checkTid();
        collectData(request);

        Encrypt0Message enc = prepareCOSEStructure(confidential, aad, tid);

        byte[] protectedPayload = null;
        try {
            protectedPayload = encryptAndEncode(enc, tid);
        } catch (CoseException e) {
            e.printStackTrace();
            System.exit(1);
        }

        setOSPayload(protectedPayload, request);
        return request;
    }

    protected byte[] serializeAAD(){
        int code = request.getCode().value;
        String uri = request.getURI();
        return OSSerializer.serializeRequestAdditionalAuthenticatedData(code, tid, uri);
    }


    private Encrypt0Message prepareCOSEStructure(byte[] confidential, byte[] aad, OSTid tid) {
        Encrypt0Message enc = new Encrypt0Message();
        enc.SetContent(confidential);
        enc.setExternal(aad);
        enc.addAttribute(HeaderKeys.KID, CBORObject.FromObject(tid.getCid()), Attribute.ProtectedAttributes);
        return enc;
    }
}
