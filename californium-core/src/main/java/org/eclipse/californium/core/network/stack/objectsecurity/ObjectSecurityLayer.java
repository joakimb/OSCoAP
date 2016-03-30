package org.eclipse.californium.core.network.stack.objectsecurity;

import COSE.CoseException;
import org.eclipse.californium.core.coap.*;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.serialization.DatagramReader;
import org.eclipse.californium.core.network.stack.AbstractLayer;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSSequenceNumberException;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;

import java.math.BigInteger;
import java.util.List;

/**
 * Created by joakim on 04/02/16.
 */
public class ObjectSecurityLayer extends AbstractLayer {

    OSTidDB db;

    public ObjectSecurityLayer(){
        db = OSHashMapTIDDB.getDB();
    }

    public void prepareSend(Message message, OSTid tid, int code) throws OSTIDException{
        OptionSet options = message.getOptions();
        if (options.hasOption(OptionNumberRegistry.OBJECT_SECURITY)) {

            //This cast is ok since we explicity initialize an OSOption when sending
            ObjectSecurityOption osOpt = (ObjectSecurityOption) filterOSOption(options);



           //OSTid tid = db.getTID(BigInteger.ONE.toByteArray());

            if (tid == null) {
                System.out.print("TID NOT PRESENT, ABORTING");
                System.exit(1);
                //TODO change behaviour to ignore OS or throw Exception earlier i chain, e.g. in CoapClient.java
            } else {
                byte[] confidential = OSSerializer.serializeConfidentialData(options, message.getPayload());
                byte[] aad = OSSerializer.serializeAdditionalAuthenticatedData(code, tid);
                byte[] protectedPayload = null;
                try {
                    protectedPayload = osOpt.encryptAndEncode(confidential, aad, tid);
                } catch (CoseException e) {
                    e.printStackTrace();
                }
                if(message.getPayloadSize() > 0){
                    osOpt.setValue(new byte[0]);
                    message.setPayload(protectedPayload);
                } else {
                    osOpt.setValue(protectedPayload);
                    message.setPayload(new byte[0]);
                }
                message.setOptions(juggleOptions(options, osOpt));

            }

        }
    }

    public void prepareReceive(Message message, int code){
        OptionSet options = message.getOptions();
        Option o = filterOSOption(options);
        if ( o != null) {

            ObjectSecurityOption op = new ObjectSecurityOption(o);

            byte[] protectedData = op.getLength() == 0 ? message.getPayload() : op.getValue();

            byte[] content = new byte[0];
            try {
                content = op.decryptAndDecode(protectedData, code);
            } catch (OSSequenceNumberException e) {
                e.printStackTrace();
                System.exit(1);
            }
            List<Option> optionList = OSSerializer.readConfidentialOptions(content);
            for (Option option : optionList) {
                message.getOptions().addOption(option);
            }
            byte[] payload = OSSerializer.readPayload(content);
            message.setPayload(payload);
            System.out.println("PAYLOAD DECRYPTED: ");
            System.out.println(bytesToHex(payload));
        }

    }

    private OptionSet juggleOptions(OptionSet options, ObjectSecurityOption osOpt) {
        //TODO, this is a bit stupid
        boolean hasProxyUri = options.hasProxyUri();
        String proxyUri = null;
        if (hasProxyUri) {
            proxyUri = options.getProxyUri();
            options.removeProxyUri();
        }
        boolean hasMaxAge = options.hasMaxAge();
        if (hasMaxAge) {
            options.removeMaxAge();
        }
        options.clear();
        options.addOption(osOpt);
        if (hasProxyUri) {
            options.setProxyUri(proxyUri);
        }
        if (hasMaxAge) {
            options.setMaxAge(0);
        }
        return options;
    }

    public static Option filterOSOption(OptionSet options){
        if (options.hasOption(OptionNumberRegistry.OBJECT_SECURITY)) {
            for (Option o : options.asSortedList()) {
                if (o.getNumber() == OptionNumberRegistry.OBJECT_SECURITY) {
                    return o;
                }
            }
        }
        return null;
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

    @Override
    public void sendRequest(Exchange exchange, Request request){
        try {
            String uri = request.getURI();
            OSTid tid = db.getTID(uri);
            exchange.setCryptographicContextID(tid.getCid());
            prepareSend(request, tid, request.getCode().value);
        } catch (OSTIDException e) {
            //TODO fail gracefully
            e.printStackTrace();
            System.exit(1);
        }
        super.sendRequest(exchange, request);
    }


    @Override
    public void sendResponse(Exchange exchange, Response response) {
        if(exchange.getCurrentRequest().getOptions().hasOption(OptionNumberRegistry.OBJECT_SECURITY)){
            response.getOptions().addOption(new ObjectSecurityOption());
        }
        try {
            OSTid tid = db.getTID(exchange.getCryptgraphicContextID());
            prepareSend(response, tid, response.getCode().value);
        } catch (OSTIDException e) {
            //TODO fail gracefully
            e.printStackTrace();
            System.exit(1);
        }
        super.sendResponse(exchange,response);
    }

    @Override
    public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
        super.sendEmptyMessage(exchange,message);
    }

    @Override
    public void receiveRequest(Exchange exchange, Request request) {
       prepareReceive(request, request.getCode().value);
       super.receiveRequest(exchange, request);
    }

    @Override
    public void receiveResponse(Exchange exchange, Response response) {
        prepareReceive(response, response.getCode().value);
        super.receiveResponse(exchange,response);
    }

    @Override
    public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
        super.receiveEmptyMessage(exchange, message);
    }




}
