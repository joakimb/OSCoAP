package org.eclipse.californium.core.network.stack.objectsecurity.Encryption;

import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;
import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.stack.objectsecurity.*;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSException;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSSequenceNumberException;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;

/**
 * Created by joakim on 06/04/16.
 */
public class RequestDecryptor extends Decryptor {

    Request request;
    Encrypt0Message enc;

    public RequestDecryptor(Request request) {
        this.request = request;
    }

    public byte[] decrypt() {


        //TODO check seq validity
        collectData(request);
        enc = prepareCOSEStructure();

        byte[] content = new byte[0];
        try {
            content = decryptAndDecode(enc);

        } catch (OSSequenceNumberException e) {
            e.printStackTrace();
            System.exit(1);
        } catch (OSTIDException e) {
            e.printStackTrace();
            System.exit(1);
        } catch (OSException e) {
            e.printStackTrace();
            System.exit(1);
        }
        OptionSet optionSet = OptionJuggle.readOptionsFromOSPayload(content);
        request.setOptions(optionSet);
        byte[] payload = OSSerializer.readPayload(content);
        request.setPayload(payload);

        byte[] cid = null;

        try {
            cid = getTid().getCid();
        } catch (OSException e) {
            e.printStackTrace();
            System.exit(1);
        }

        return cid;
    }

    protected OSTid getTid() throws OSException {
        if (enc == null) {
            throw new OSException("enc not initialized");
        }
        byte[] cid = (enc.findAttribute(HeaderKeys.KID)).GetByteString();
        OSTid tid = OSHashMapTIDDB.getDB().getTID(cid);
        return tid;
    }

    protected byte[] serializeAAD(OSTid tid) {
        return OSSerializer.serializeRequestAdditionalAuthenticatedData(request.getCode().value, tid, request.getURI());
    }
}