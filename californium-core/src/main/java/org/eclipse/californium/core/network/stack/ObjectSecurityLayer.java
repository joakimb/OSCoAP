package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.coap.*;
import org.eclipse.californium.core.network.Exchange;

/**
 * Created by joakim on 04/02/16.
 */
public class ObjectSecurityLayer extends AbstractLayer {

    public ObjectSecurityLayer() {

        //lägg in OSCOAP som non critical option
        //message.getOptions()."addOSec....
    }
    @Override
    public void sendRequest(Exchange exchange, Request request) {
       OptionSet options = request.getOptions();
        byte[] optionData = new byte[0];
        //optionData[0] = (byte) 0xFF;
        options.addOption(new Option(OptionNumberRegistry.OBJECT_SECURITY, optionData));
        getHeaderStart(request);
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

    private byte[] getHeaderStart(Request request){
        byte headerInit[] = request.getBytes();
            //System.out.println("Bytes: " + headerInit[0]);
            return headerInit;
        }

}
