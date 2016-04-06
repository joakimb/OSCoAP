package org.eclipse.californium.core.network.stack.objectsecurity;

import COSE.Attribute;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;
import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;

/**
 * Created by joakim on 06/04/16.
 */
public class ResponseEncryptor extends Encryptor{
    Response response;

    public ResponseEncryptor(Response response, OSTid tid){
        this.tid = tid;
        this.response = response;
    }

    public Response encrypt() throws OSTIDException {

        checkTid();
        collectData(response);

        Encrypt0Message enc = prepareCOSEStructure(confidential, aad, tid);

        byte[] protectedPayload = null;
        try {
            protectedPayload = encryptAndEncode(enc, tid);
        } catch (CoseException e) {
            e.printStackTrace();
            System.exit(1);
        }

        setOSPayload(protectedPayload, response);
        return response;
    }

    protected byte[] serializeAAD(){
        int code = response.getCode().value;
        return OSSerializer.serializeSendResponseAdditionalAuthenticatedData(code, tid);
    }


    private Encrypt0Message prepareCOSEStructure(byte[] confidential, byte[] aad, OSTid tid) {
        Encrypt0Message enc = new Encrypt0Message();
        enc.SetContent(confidential);
        enc.setExternal(aad);
        return enc;
    }
}
