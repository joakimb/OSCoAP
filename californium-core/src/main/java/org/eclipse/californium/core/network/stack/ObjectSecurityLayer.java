package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
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
        byte[] optionData = new byte[30];
        options.addOption(new Option(OptionNumberRegistry.OBJECT_SECURITY, optionData));

        super.sendRequest(exchange, request);

    }




}
