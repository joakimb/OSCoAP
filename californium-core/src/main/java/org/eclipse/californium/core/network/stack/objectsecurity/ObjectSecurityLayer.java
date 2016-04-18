package org.eclipse.californium.core.network.stack.objectsecurity;

import org.eclipse.californium.core.coap.*;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.stack.AbstractLayer;
import org.eclipse.californium.core.network.stack.objectsecurity.Encryption.RequestDecryptor;
import org.eclipse.californium.core.network.stack.objectsecurity.Encryption.RequestEncryptor;
import org.eclipse.californium.core.network.stack.objectsecurity.Encryption.ResponseDecryptor;
import org.eclipse.californium.core.network.stack.objectsecurity.Encryption.ResponseEncryptor;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSSequenceNumberException;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;

/**
 * Created by joakim on 04/02/16.
 */
public class ObjectSecurityLayer extends AbstractLayer {

    //CryptoContextDB db;

    //public ObjectSecurityLayer(){
     //   db = HashMapCryptoContextDB.getDB();
    //}

    public Request prepareSend(Request message, CryptoContext tid) throws OSTIDException, OSSequenceNumberException {

        RequestEncryptor encryptor = new RequestEncryptor(message, tid);
        return encryptor.encrypt();

    }

    public Response prepareSend(Response message, CryptoContext tid) throws OSTIDException, OSSequenceNumberException {
        ResponseEncryptor encryptor = new ResponseEncryptor(message, tid);
        return encryptor.encrypt();

    }

    public byte[] prepareReceive(Request request, CryptoContextDB db) throws OSTIDException, OSSequenceNumberException {

        RequestDecryptor decryptor = new RequestDecryptor(db, request);
        return decryptor.decrypt();

    }

    public void prepareReceive(Response response, CryptoContext tid) throws OSTIDException, OSSequenceNumberException {

        ResponseDecryptor decryptor = new ResponseDecryptor(response);
        decryptor.decrypt(tid);
    }



    @Override
    public void sendRequest(Exchange exchange, Request request){

        if(shouldProtectRequest(request)){
           try {
                String uri = request.getURI();
                CryptoContext tid = exchange.getCryptographicContextDB().getContext(uri);
                //make sure we can find Security Context for associated Response
                exchange.setCryptographicContextID(tid.getCid());
                request = prepareSend(request, tid);
            } catch (OSTIDException e) {
                //TODO fail gracefully
                e.printStackTrace();
                System.exit(1);
            } catch (OSSequenceNumberException e) {
               e.printStackTrace();
               System.exit(1);
           }
        }
        super.sendRequest(exchange, request);
    }


    @Override
    public void sendResponse(Exchange exchange, Response response) {

        if(shouldProtectResponse(exchange)) {
            response.getOptions().addOption(new Option(OptionNumberRegistry.OBJECT_SECURITY));

            try {
                CryptoContext tid = exchange.getCryptographicContextDB().getContext(exchange.getCryptgraphicContextID());
                prepareSend(response, tid);
            } catch (OSTIDException e) {
                //TODO fail gracefully
                e.printStackTrace();
                System.exit(1);
            } catch (OSSequenceNumberException e) {
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
                cid = prepareReceive(request, exchange.getCryptographicContextDB());
            } catch (OSTIDException e) {
                //TODO fail gracefully
                e.printStackTrace();
                System.exit(1);
            } catch (OSSequenceNumberException e) {
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
                CryptoContext tid = exchange.getCryptographicContextDB().getContext(exchange.getCryptgraphicContextID());
                prepareReceive(response, tid);
            } catch (OSTIDException e) {
                //TODO fail gracefully
                e.printStackTrace();
                System.exit(1);
            } catch (OSSequenceNumberException e) {
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
        return exchange.getCryptgraphicContextID() != null;
    }

    private boolean shouldProtectRequest(Request request){
        OptionSet options = request.getOptions();
        return options.hasOption(OptionNumberRegistry.OBJECT_SECURITY);

    }

    private boolean isProtected(Message message){
        return OptionJuggle.filterOSOption(message.getOptions()) != null;
    }
}
