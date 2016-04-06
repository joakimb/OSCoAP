package org.eclipse.californium.core.network.stack.objectsecurity;

import org.eclipse.californium.core.coap.*;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.stack.AbstractLayer;
import org.eclipse.californium.core.network.stack.objectsecurity.Encryption.RequestEncryptor;
import org.eclipse.californium.core.network.stack.objectsecurity.Encryption.ResponseEncryptor;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSSequenceNumberException;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;

/**
 * Created by joakim on 04/02/16.
 */
public class ObjectSecurityLayer extends AbstractLayer {

    OSTidDB db;

    public ObjectSecurityLayer(){
        db = OSHashMapTIDDB.getDB();
    }

    public Request prepareSend(Request message, OSTid tid) throws OSTIDException {

        RequestEncryptor encryptor = new RequestEncryptor(message, tid);
        return encryptor.encrypt();

    }

    public Response prepareSend(Response message, OSTid tid) throws OSTIDException {
        ResponseEncryptor encryptor = new ResponseEncryptor(message, tid);
        return encryptor.encrypt();

    }

    public byte[] prepareReceive(Request req) throws OSTIDException {

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
            OptionSet optionSet = OptionJuggle.readOptionsFromOSPayload(content);
            req.setOptions(optionSet);
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
            OptionSet optionSet = OptionJuggle.readOptionsFromOSPayload(content);
            response.setOptions(optionSet);

            byte[] payload = OSSerializer.readPayload(content);
            response.setPayload(payload);
            return tid.getCid();
        }
        return null;
    }



    @Override
    public void sendRequest(Exchange exchange, Request request){

        if(shouldProtectRequest(request)){
           try {
                String uri = request.getURI();
                OSTid tid = db.getTID(uri);
                //make sure we can find Security Context for associated Response
                exchange.setCryptographicContextID(tid.getCid());
                request = prepareSend(request, tid);
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
        if (isProtected(request)) {
            byte[] cid = null;
            try {
                cid = prepareReceive(request);
            } catch (OSTIDException e) {
                //TODO fail gracefully
                e.printStackTrace();
                System.exit(1);
            }
            exchange.setCryptographicContextID(cid);
        }
       super.receiveRequest(exchange, request);
    }

    @Override
    public void receiveResponse(Exchange exchange, Response response) {
        if (isProtected(response)) {
            try {
                OSTid tid = db.getTID(exchange.getCryptgraphicContextID());
                prepareReceive(response, tid);
            } catch (OSTIDException e) {
                //TODO fail gracefully
                e.printStackTrace();
                System.exit(1);
            }
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

    private boolean isProtected(Message message){
        return OptionJuggle.filterOSOption(message.getOptions()) != null;
    }
}
