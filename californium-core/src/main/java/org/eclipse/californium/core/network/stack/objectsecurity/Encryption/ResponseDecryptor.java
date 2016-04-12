package org.eclipse.californium.core.network.stack.objectsecurity.Encryption;

import COSE.Encrypt0Message;
import COSE.HeaderKeys;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.stack.objectsecurity.*;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSException;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSSequenceNumberException;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;

/**
 * Created by joakim on 07/04/16.
 */
public class ResponseDecryptor extends Decryptor {

    Response response;
    byte[] seq;
    CryptoContext tid;

    public ResponseDecryptor(Response response){
        this.response = response;
    }

    public void decrypt(CryptoContext tid){
        collectData(response);
        this.tid = tid;
        Encrypt0Message enc = prepareCOSEStructure();
        seq = (enc.findAttribute(HeaderKeys.PARTIAL_IV)).GetByteString();
        byte[] content = new byte[0];
        try {
            content = decryptAndDecode(enc);

        } catch (OSSequenceNumberException e) {
            e.printStackTrace();
            System.exit(1);
        } catch (OSException e) {
            e.printStackTrace();
            System.exit(1);
        } catch (OSTIDException e) {
            e.printStackTrace();
            System.exit(1);
        }
        OptionSet optionSet = OptionJuggle.readOptionsFromOSPayload(content);
        response.setOptions(optionSet);

        byte[] payload = OSSerializer.readPayload(content);
        response.setPayload(payload);
    }

    @Override
    protected byte[] serializeAAD(CryptoContext tid) {
        return OSSerializer.serializeReceiveResponseAdditionalAuthenticatedData(response.getCode().value, tid, seq);
    }

    @Override
    protected CryptoContext getTid() throws OSException {
        return tid;
    }
}
