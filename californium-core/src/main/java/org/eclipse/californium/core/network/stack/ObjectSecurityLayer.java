package org.eclipse.californium.core.network.stack;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import org.eclipse.californium.core.coap.*;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.serialization.DataSerializer;
import org.eclipse.californium.core.network.serialization.DatagramWriter;
import org.eclipse.californium.core.network.serialization.Serializer;
import org.eclipse.californium.core.objectsecurity.OSSerializer;

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
        CBORFactory f = new CBORFactory();
        ObjectMapper mapper = new ObjectMapper(f);
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




}
