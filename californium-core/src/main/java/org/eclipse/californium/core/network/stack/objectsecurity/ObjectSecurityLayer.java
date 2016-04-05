package org.eclipse.californium.core.network.stack.objectsecurity;

import COSE.CoseException;
import org.eclipse.californium.core.coap.*;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.stack.AbstractLayer;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSSequenceNumberException;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;

import java.util.List;

/**
 * Created by joakim on 04/02/16.
 */
public class ObjectSecurityLayer extends AbstractLayer {

    OSTidDB db;

    public ObjectSecurityLayer(){
        db = OSHashMapTIDDB.getDB();
    }

    public void prepareSend(Request message, OSTid tid) throws OSTIDException {
        OptionSet options = message.getOptions();
        byte[] aad = OSSerializer.serializeRequestAdditionalAuthenticatedData(message.getCode().value, tid, message.getURI());
        //This cast is ok since we explicity initialize an OSOption when sending
        ObjectSecurityOption osOpt = OptionJuggle.filterOSOption(options);

        if (tid == null) {
            System.out.print("TID NOT PRESENT, ABORTING");
            System.exit(1);
            //TODO change behaviour to ignore OS or throw Exception earlier i chain, e.g. in CoapClient.java
        } else {
            byte[] confidential = OSSerializer.serializeConfidentialData(options, message.getPayload());
            byte[] protectedPayload = null;
            try {
                protectedPayload = osOpt.encryptAndEncodeRequest(confidential,aad,tid);
            } catch (CoseException e) {
                e.printStackTrace();
                System.exit(1);
            }
            if (message.getPayloadSize() > 0) {
                osOpt.setValue(new byte[0]);
                message.setPayload(protectedPayload);
            } else {
                osOpt.setValue(protectedPayload);
                message.setPayload(new byte[0]);
            }
            message.setOptions(OptionJuggle.moveOptionsToOSPayload(options));

        }


    }

    public void prepareSend(Response message, OSTid tid) throws OSTIDException {
        OptionSet options = message.getOptions();
        byte[] aad = OSSerializer.serializeSendResponseAdditionalAuthenticatedData(message.getCode().value, tid);
        //This cast is ok since we explicity initialize an OSOption when sending
        ObjectSecurityOption osOpt = OptionJuggle.filterOSOption(options);

        if (tid == null) {
            System.out.print("TID NOT PRESENT, ABORTING");
            System.exit(1);
            //TODO change behaviour to ignore OS or throw Exception earlier i chain, e.g. in CoapClient.java
        } else {
            byte[] confidential = OSSerializer.serializeConfidentialData(options, message.getPayload());
            byte[] protectedPayload = null;
            try {
                protectedPayload = osOpt.encryptAndEncodeResponse(confidential, aad, tid);
            } catch (CoseException e) {
                e.printStackTrace();
                System.exit(1);
            }
            if (message.getPayloadSize() > 0) {
                osOpt.setValue(new byte[0]);
                message.setPayload(protectedPayload);
            } else {
                osOpt.setValue(protectedPayload);
                message.setPayload(new byte[0]);
            }
            message.setOptions(OptionJuggle.moveOptionsToOSPayload(options));

        }


    }

    public byte[] prepareReceive(Request req) throws OSTIDException {
        //todo
        //h'mta cid fr[n kid i enc0msg                 cid = op.extcractCidFromProtected(protectedData);

        OptionSet options = req.getOptions();
        Option o = OptionJuggle.filterOSOption(options);

        //byte[] cid = null;

        if ( o != null) {

            ObjectSecurityOption op = new ObjectSecurityOption(o);

            byte[] protectedData = op.getLength() == 0 ? req.getPayload() : op.getValue();
            //TODO check seq validity
            byte[] cid = ObjectSecurityOption.extractCidFromProtected(protectedData);
            OSTid tid = db.getTID(cid);

            //byte[] seq = ObjectSecurityOption.extractSeqFromProtected(protectedData);

            byte[] aad = OSSerializer.serializeRequestAdditionalAuthenticatedData(req.getCode().value, tid, req.getURI());
            byte[] content = new byte[0];
            try {
                content = op.decryptAndDecodeRequest(protectedData, aad);

            } catch (OSSequenceNumberException e) {
                e.printStackTrace();
                System.exit(1);
            }
            List<Option> optionList = OSSerializer.readConfidentialOptions(content);
            for (Option option : optionList) {
                req.getOptions().addOption(option);
            }
            byte[] payload = OSSerializer.readPayload(content);
            req.setPayload(payload);
            return cid;
        }
        return null;
    }
    public byte[] prepareReceive(Response response, OSTid tid) throws OSTIDException {

        OptionSet options = response.getOptions();
        Option o = OptionJuggle.filterOSOption(options);

        //byte[] cid = null;

        if ( o != null) {

            ObjectSecurityOption op = new ObjectSecurityOption(o);

            byte[] protectedData = op.getLength() == 0 ? response.getPayload() : op.getValue();

            byte[] seq = ObjectSecurityOption.extractSeqFromProtected(protectedData);
            byte[] aad = OSSerializer.serializeReceiveResponseAdditionalAuthenticatedData(response.getCode().value, tid, seq);
            byte[] content = new byte[0];
            try {
                content = op.decryptAndDecodeResponse(protectedData, aad, tid);

            } catch (OSSequenceNumberException e) {
                e.printStackTrace();
                System.exit(1);
            }
            List<Option> optionList = OSSerializer.readConfidentialOptions(content);
            for (Option option : optionList) {
                response.getOptions().addOption(option);
            }
            byte[] payload = OSSerializer.readPayload(content);
            response.setPayload(payload);
            return tid.getCid();
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

        if(shouldProtectRequest(request)){
           try {
                String uri = request.getURI();
                OSTid tid = db.getTID(uri);
                //make sure we can find Security Context for associated Response
                exchange.setCryptographicContextID(tid.getCid());
                prepareSend(request, tid);
            } catch (OSTIDException e) {
                //TODO fail gracefully
                e.printStackTrace();
                System.exit(1);
            }
        }
        super.sendRequest(exchange, request);
    }


    @Override
    public void sendResponse(Exchange exchange, Response response) {

        if(shouldProtectResponse(exchange)) {

            response.getOptions().addOption(new ObjectSecurityOption());

            try {
                OSTid tid = db.getTID(exchange.getCryptgraphicContextID());
                prepareSend(response, tid);
            } catch (OSTIDException e) {
                //TODO fail gracefully
                e.printStackTrace();
                System.exit(1);
            }
        }

        super.sendResponse(exchange,response);
    }

    @Override
    public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
        super.sendEmptyMessage(exchange,message);
    }

    @Override
    public void receiveRequest(Exchange exchange, Request request) {
        //TODO break if no OSOpt
        byte[] cid = null;
        try {
            cid = prepareReceive(request);
        } catch (OSTIDException e) {
            //TODO fail gracefully
            e.printStackTrace();
            System.exit(1);
        }
       exchange.setCryptographicContextID(cid);
       super.receiveRequest(exchange, request);
    }

    @Override
    public void receiveResponse(Exchange exchange, Response response) {
        //TODO break if no OSOpt
        try {
            OSTid tid = db.getTID(exchange.getCryptgraphicContextID());
            prepareReceive(response, tid);
        } catch (OSTIDException e) {
            //TODO fail gracefully
            e.printStackTrace();
            System.exit(1);
        }
        super.receiveResponse(exchange,response);
    }

    @Override
    public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
        super.receiveEmptyMessage(exchange, message);
    }

    private boolean shouldProtectResponse(Exchange exchange){
        return exchange.getCurrentRequest().getOptions().hasOption(OptionNumberRegistry.OBJECT_SECURITY);
    }

    private boolean shouldProtectRequest(Request request){
        OptionSet options = request.getOptions();
        return options.hasOption(OptionNumberRegistry.OBJECT_SECURITY);

    }

}
