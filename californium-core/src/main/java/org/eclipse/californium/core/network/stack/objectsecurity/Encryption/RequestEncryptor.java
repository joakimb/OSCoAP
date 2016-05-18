package org.eclipse.californium.core.network.stack.objectsecurity.Encryption;

import COSE.Attribute;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;
import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.stack.objectsecurity.OSSerializer;
import org.eclipse.californium.core.network.stack.objectsecurity.CryptoContext;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSSequenceNumberException;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;

/**
 * Created by joakim on 06/04/16.
 */
public class RequestEncryptor extends Encryptor {

    Request request;

    public RequestEncryptor(Request request, CryptoContext tid){
        this.tid = tid;
        this.request = request;
    }

    public Request encrypt() throws OSSequenceNumberException, OSTIDException {

        checkTid();
        tid.increaseSenderSeq();
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
        byte[] aad = OSSerializer.serializeRequestAdditionalAuthenticatedData(code, tid, uri);
        System.out.println("aad" +bytesToHex(aad));
        return null;
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


    private Encrypt0Message prepareCOSEStructure(byte[] confidential, byte[] aad, CryptoContext tid) {
        Encrypt0Message enc = new Encrypt0Message();
        enc.SetContent(confidential);
        //enc.setExternal(aad);
        enc.addAttribute(HeaderKeys.KID, CBORObject.FromObject(tid.getCid()), Attribute.ProtectedAttributes);
        System.out.println("KID: " + bytesToHex(tid.getCid()));
        return enc;
    }
}
