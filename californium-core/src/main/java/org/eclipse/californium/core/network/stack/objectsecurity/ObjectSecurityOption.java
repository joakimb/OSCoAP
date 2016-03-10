package org.eclipse.californium.core.network.stack.objectsecurity;

import COSE.*;
import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.coap.*;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.network.serialization.DatagramWriter;

import java.util.List;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.*;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.CODE_BITS;

/**
 * Created by joakim on 2016-02-23.
 */
public class ObjectSecurityOption extends Option{

    private OSTid tid;
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

    public void setTid(OSTid tid){
        this.tid = tid;
    }

    public void encryptAndEncode(){
        Encrypt0Message enc = new Encrypt0Message();
        byte[] tmp = new byte[32];
        enc.SetContent(tmp);
        enc.addAttribute(HeaderKeys.Algorithm, tid.getAlg(), Attribute.DontSendAttributes);
        try {
            byte[] key = tid.getSenderKey();
            enc.Encrypt(key);
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

    public static byte[] decryptAndDecode(byte[] payload, OSTid tid){

        Encrypt0Message enc = new Encrypt0Message();
        try {
            enc.DecodeFromCBORObject(CBORObject.DecodeFromBytes(payload));
        } catch (CoseException e) {
            e.printStackTrace();
        }
        enc.addAttribute(HeaderKeys.Algorithm, tid.getAlg(), Attribute.DontSendAttributes);
        byte[] result = null;
        try {
            byte[] key = tid.getReceiverKey();
            result = enc.Decrypt(key);
        } catch (CoseException e) {
            e.printStackTrace();
            System.exit(1);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }
        return result;

    }
   private byte[] getRequestMac0AuthenticatedData(Message message, int code){
        DatagramWriter writer = new DatagramWriter();

        writeSMHeader(writer);
        writeCoAPHeader(writer, code);
        writeOptions(writer, message);
        writePayload(writer, message);

        return writer.toByteArray();
    }

    //
    private void writeSMHeader(DatagramWriter writer ){
        writer.writeBytes(tid.getCid());
        writer.writeBytes(tid.getSenderSeq().toByteArray());
    }

    //first 2 bytes of header with Type and Token Length bits set to 0
    private void writeCoAPHeader(DatagramWriter writer, int code){


        writer.write(VERSION, VERSION_BITS);
        writer.write(0, TYPE_BITS);
        writer.write(0,TOKEN_LENGTH_BITS);
        writer.write(code, CODE_BITS);
    }

    //TODO filter options not supposed to be integrity protected
    //all CoAP options present which are to be Integrity
    //Protected according to draft-selander-ace-object-security-03
    //in the order given by the option number
    private void writeOptions(DatagramWriter writer, Message message){
        List<Option> options = message.getOptions().asSortedList(); // already sorted
        int previousOptionNumber = 0;
        for (Option option : options) {

            // write 4-bit option delta
            int optionDelta = option.getNumber() - previousOptionNumber;
            int optionDeltaNibble = getOptionNibble(optionDelta);
            writer.write(optionDeltaNibble, OPTION_DELTA_BITS);

            // write 4-bit option length
            int optionLength = option.getLength();
            int optionLengthNibble = getOptionNibble(optionLength);
            writer.write(optionLengthNibble, OPTION_LENGTH_BITS);

            // write extended option delta field (0 - 2 bytes)
            if (optionDeltaNibble == 13) {
                writer.write(optionDelta - 13, 8);
            } else if (optionDeltaNibble == 14) {
                writer.write(optionDelta - 269, 16);
            }

            // write extended option length field (0 - 2 bytes)
            if (optionLengthNibble == 13) {
                writer.write(optionLength - 13, 8);
            } else if (optionLengthNibble == 14) {
                writer.write(optionLength - 269, 16);
            }

            // write option value
            writer.writeBytes(option.getValue());

            // update last option number
            previousOptionNumber = option.getNumber();
        }
    }

    //payload
    private void writePayload(DatagramWriter writer, Message message){
        //TODO test with payload
        byte[] payload = message.getPayload();
        if (payload != null && payload.length > 0) {
            // if payload is present and of non-zero length, it is prefixed by
            // an one-byte Payload Marker (0xFF) which indicates the end of
            // options and the start of the payload
            writer.writeByte(PAYLOAD_MARKER);
            writer.writeBytes(payload);
        }
    }

    //from DatagramWriter
     /**
     * Returns the 4-bit option header value.
     *
     * @param optionValue
     *            the option value (delta or length) to be encoded.
     * @return the 4-bit option header value.
     */
    private int getOptionNibble(int optionValue) {
        if (optionValue <= 12) {
            return optionValue;
        } else if (optionValue <= 255 + 13) {
            return 13;
        } else if (optionValue <= 65535 + 269) {
            return 14;
        } else {
            throw new IllegalArgumentException("Unsupported option delta "+optionValue);
        }
    }

}
