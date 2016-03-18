package org.eclipse.californium.core.network.stack.objectsecurity;

import org.eclipse.californium.core.coap.*;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.serialization.DatagramReader;
import org.eclipse.californium.core.network.stack.AbstractLayer;

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

    @Override
    public void sendRequest(Exchange exchange, Request request){
        OptionSet options = request.getOptions();
        if (options.hasOption(OptionNumberRegistry.OBJECT_SECURITY)) {
            //This cast is ok since we explicity initialize an OSOption when sending
            //TODO, make so that cast possible when receiving
            ObjectSecurityOption osOpt = (ObjectSecurityOption) filterOSOption(options);

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



            OSTid tid = db.getTID(BigInteger.ONE.toByteArray());

            if (tid == null) {
                //throw new OSTIDException("No Context for URI.");
                System.out.print("TID NOT FOUND ABORTING");
                System.exit(1);
                //TODO change behaviour to ignore OS or throw Exception earlier i chain,
                // e.g. in CoapClient.java
            } else {
                byte[] confidential = OSSerializer.serializeConfidentialData(options, request.getPayload());
                byte[] aad = OSSerializer.serializeAdditionalAuthenticatedData(request.getCode().value, tid);

                osOpt.encryptAndEncode(confidential, aad, tid);
                options.clear();
                options.addOption(osOpt);
                if (hasProxyUri) {
                    options.setProxyUri(proxyUri);
                }
                if (hasMaxAge) {
                    options.setMaxAge(0);
                }
                request.setPayload(new byte[0]);
            }

        }
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

        OptionSet options = request.getOptions();
        Option o = filterOSOption(options);
        if ( o != null) {

            ObjectSecurityOption op = new ObjectSecurityOption(o);

            byte[] content = op.decryptAndDecode(op.getValue(), request.getCode().value);
            List<Option> optionList = OSSerializer.readConfidentialOptions(content);
            for (Option option : optionList) {
                request.getOptions().addOption(option);
            }
            byte[] payload = OSSerializer.readPayload(content);
            request.setPayload(payload);
            System.out.println("PAYLOAD DECRYPTED: ");
            System.out.println(bytesToHex(content));
        }
        super.receiveRequest(exchange, request);
    }

    @Override
    public void receiveResponse(Exchange exchange, Response response) {
        super.receiveResponse(exchange,response);
    }

    @Override
    public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
        super.receiveEmptyMessage(exchange, message);
    }

    private static Option filterOSOption(OptionSet options){
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




}
