package org.eclipse.californium.core.objectsecurity;

import COSE.*;
import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.coap.*;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.network.serialization.DatagramWriter;

import java.util.List;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.*;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.PAYLOAD_MARKER;

/**
 * Created by joakim on 2016-02-10.
 */
public class OSSerializer {

    DatagramWriter writer;

    public OSSerializer(){
        writer = new DatagramWriter();
    }

    public byte[] signMessage(Message message){
        String content = "This is the content";
        byte[] key = { 'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                15, 16, 17, 18, 19,
                20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
        MAC0Message mac = new MAC0Message();
        mac.SetContent(content);
        mac.addAttribute(HeaderKeys.Algorithm, AlgorithmID.HMAC_SHA_256_64.AsCBOR(), Attribute.DontSendAttributes);
        try {
            mac.Create(key);
        } catch (CoseException e){

        }
        return null; //TODO
    }

    //TODO should code zero be allowed?
    public byte[] serializeRequest(Request request) {
        writer = new DatagramWriter();
        CoAP.Code code = request.getCode();
        return serializeMessage(request, code == null ? 0 : code.value);
    }

    public byte[] serializeResponse(Response response) {
        writer = new DatagramWriter();
        return serializeMessage(response, response.getCode().value);
    }

    public byte[] serializeEmptyMessage(Message message) {
        writer = new DatagramWriter();
        return serializeMessage(message, 0);
    }

    private byte[] serializeMessage(Message message, int code) {
        //SM Header

        //TODO

       //first 2 bytes of header with Type and Token Length bits set to 0
        writer.write(VERSION, VERSION_BITS);
        writer.write(0, TYPE_BITS);
        writer.write(0,TOKEN_LENGTH_BITS);
        writer.write(code, CODE_BITS);

        //all CoAP options present which are to be Integrity
        //Protected according to draft-selander-ace-object-security-03
        //in the order given by the option number
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

        //payload
        //TODO test wlith payload
        byte[] payload = message.getPayload();
        if (payload != null && payload.length > 0) {
            // if payload is present and of non-zero length, it is prefixed by
            // an one-byte Payload Marker (0xFF) which indicates the end of
            // options and the start of the payload
            writer.writeByte(PAYLOAD_MARKER);
            writer.writeBytes(payload);
        }
        return writer.toByteArray();

        // Transaction Identifier
        //TODO
    }

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
