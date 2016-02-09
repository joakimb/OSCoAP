package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.coap.*;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.serialization.DataSerializer;
import org.eclipse.californium.core.network.serialization.DatagramWriter;
import org.eclipse.californium.core.network.serialization.Serializer;

import java.util.List;
import java.util.Random;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.*;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.OPTION_LENGTH_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.PAYLOAD_MARKER;

/**
 * Created by joakim on 04/02/16.
 */
public class ObjectSecurityLayer extends AbstractLayer {

    OSSerializer serializer;

    public ObjectSecurityLayer() {
        serializer = new OSSerializer();
    }

    @Override
    public void sendRequest(Exchange exchange, Request request) {
       OptionSet options = request.getOptions();
        byte[] optionData = new byte[1];
        optionData[0] = (byte) 0x00;
        options.addOption(new Option(OptionNumberRegistry.OBJECT_SECURITY, optionData));
        System.out.println("Bytes: " );
        byte[] serialized = serializer.serializeRequest(request);
        System.out.println(bytesToHex(serialized));
        super.sendRequest(exchange, request);
    }
    @Override
    public void sendResponse(Exchange exchange, Response response) {
        super.sendResponse(exchange,response);
    }

    @Override
    public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
        super.sendEmptyMessage(exchange,message);
    }

    @Override
    public void receiveRequest(Exchange exchange, Request request) {
        super.receiveRequest(exchange,request);
    }

    @Override
    public void receiveResponse(Exchange exchange, Response response) {
        super.receiveResponse(exchange,response);
    }

    @Override
    public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
        super.receiveEmptyMessage(exchange, message);
    }

    //TODO remove development method:
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

    private class OSSerializer {

        DatagramWriter writer;

        private OSSerializer(){
            writer = new DatagramWriter();
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


}
