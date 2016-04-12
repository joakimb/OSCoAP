package org.eclipse.californium.core.network.stack.objectsecurity;

import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.network.serialization.DatagramReader;
import org.eclipse.californium.core.network.serialization.DatagramWriter;

import java.util.ArrayList;
import java.util.List;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.*;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.PAYLOAD_MARKER;

/**
 * Created by joakim on 2016-03-17.
 */
public class OSSerializer {

    //sending
    public static byte[] serializeConfidentialData(OptionSet options, byte[] payload){
        DatagramWriter writer = new DatagramWriter();
        writeConfidentialOptions(writer, options);
        if (payload != null && payload.length > 0) {
            writePayload(writer, payload);
        }
        return writer.toByteArray();
    }

    public static byte[] serializeSendResponseAdditionalAuthenticatedData(int code, CryptoContext tid){
        DatagramWriter writer = new DatagramWriter();
        writeCoAPHeader(writer, code);
        writeAlgorithm(writer, tid);
        writer.writeBytes(tid.getCid());
        writer.writeBytes(stripZeroes(tid.getSenderSeq()));
        return writer.toByteArray();
    }

    public static byte[] serializeReceiveResponseAdditionalAuthenticatedData(int code, CryptoContext tid, byte[] seq){
        DatagramWriter writer = new DatagramWriter();
        writeCoAPHeader(writer, code);
        writeAlgorithm(writer, tid);
        writer.writeBytes(tid.getCid());
        writer.writeBytes(stripZeroes(seq));
        return writer.toByteArray();
    }


    public static byte[] serializeRequestAdditionalAuthenticatedData(int code, CryptoContext tid, String uri){
        DatagramWriter writer = new DatagramWriter();
        writeCoAPHeader(writer, code);
        writeAlgorithm(writer, tid);
        writeUri(writer, uri);
        return writer.toByteArray();
    }

    private static void writeUri(DatagramWriter writer, String uri){
       //TODO
    }

    private static void writeAlgorithm(DatagramWriter writer, CryptoContext tid){
        writer.write(tid.getAlg().AsCBOR().AsInt32(), 32);
    }

//    private static void writeReceiverTid(DatagramWriter writer, CryptoContext tid){
//        writer.writeBytes(tid.getCid());
//        writer.writeBytes(stripZeroes(tid.getReceiverSeq()));
//    }

    private static byte[] stripZeroes(byte[] in){
        if(in.length == 1) return in;
        int firstValue = 0;
        while(firstValue < in.length && in[firstValue] == 0){
            firstValue++;
        }
        byte[] out = new byte[in.length - firstValue];
        for(int i = 0; i < in.length; i++){
            out[i] = in[firstValue + i];
        }
        return out;
    }

    //first 2 bytes of header with Type and Token Length bits set to 0
    private static void writeCoAPHeader(DatagramWriter writer, int code){
        writer.write(VERSION, VERSION_BITS);
        writer.write(0, TYPE_BITS);
        writer.write(0,TOKEN_LENGTH_BITS);
        writer.write(code, CODE_BITS);
    }

    //TODO filter options not supposed to be integrity protected
    //all CoAP options present which are to be Integrity
    //Protected according to draft-selander-ace-object-security-03
    //in the order given by the option number
    private static void writeConfidentialOptions(DatagramWriter writer, OptionSet optionSet){
        List<Option> options = optionSet.asSortedList(); // already sorted
        int previousOptionNumber = 0;
        for (Option option : options) {

            //TODO Kind of a hack, refactor so that these options are not present at this stage
            if (option.getNumber() == OptionNumberRegistry.OBJECT_SECURITY) continue;
            if (option.getNumber() == OptionNumberRegistry.PROXY_URI) continue;
            if (option.getNumber() == OptionNumberRegistry.MAX_AGE) continue;

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


    public static List<Option> readConfidentialOptions(byte[] confidential) {
        DatagramReader reader = new DatagramReader(confidential);
        List<Option> optionList = new ArrayList<Option>();
        int currentOption = 0;
        byte nextByte = 0;
        while (reader.bytesAvailable()) {
            nextByte = reader.readNextByte();
            if (nextByte != PAYLOAD_MARKER) {
                // the first 4 bits of the byte represent the option delta
                int optionDeltaNibble = (0xF0 & nextByte) >> 4;
                currentOption += readOptionValueFromNibble(reader, optionDeltaNibble);

                // the second 4 bits represent the option length
                int optionLengthNibble = (0x0F & nextByte);
                int optionLength = readOptionValueFromNibble(reader, optionLengthNibble);

                // read option
                Option option = new Option(currentOption);
                option.setValue(reader.readBytes(optionLength));

                // add option to message
                optionList.add(option);
            } else break;
        }
        return optionList;
    }

    public static byte[] readPayload(byte[] confidential){

        DatagramReader reader = new DatagramReader(confidential);

        byte nextByte = 0;
        while (reader.bytesAvailable()) {
            nextByte = reader.readNextByte();
            if (nextByte == PAYLOAD_MARKER) {
                // the presence of a marker followed by a zero-length payload must be processed as a message format error
                if (!reader.bytesAvailable())
                    throw new IllegalStateException();

                // get payload
                return reader.readBytesLeft();
            }
        }
        return new byte[0];
    }

    //payload
    private static void writePayload(DatagramWriter writer, byte[] payload){
        //TODO test with payload
        if (payload != null && payload.length > 0) {
            System.out.println(" PAYLOAD PRESENT");
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
    private static int getOptionNibble(int optionValue) {
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

    //from DataParser
    /**
     * Calculates the value used in the extended option fields as specified in
     * RFC 7252, Section 3.1
     *
     * @param nibble
     *            the 4-bit option header value.
     * @return the value calculated from the nibble and the extended option
     *         value.
     */
    private static int readOptionValueFromNibble(DatagramReader reader, int nibble) {
        if (nibble <= 12) {
            return nibble;
        } else if (nibble == 13) {
            return reader.read(8) + 13;
        } else if (nibble == 14) {
            return reader.read(16) + 269;
        } else {
            throw new IllegalArgumentException("Unsupported option delta "+nibble);
        }
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

}
