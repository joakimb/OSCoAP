package org.eclipse.californium.core.network;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Matcher;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.serialization.Serializer;
import org.eclipse.californium.core.network.stack.OSCoapStack;
import org.eclipse.californium.core.network.stack.objectsecurity.OSTidDB;
import org.eclipse.californium.elements.Connector;

/**
 * Created by joakim on 12/04/16.
 */
public class OSCoapEndpoint extends CoapEndpoint{

    public OSCoapEndpoint() {
        super();
        this.coapstack = new OSCoapStack(config, new OutboxImpl());
    }

    public void sendRequest(final Request request, final OSTidDB db) {
        // always use endpoint executor
        runInProtocolStage(new Runnable() {
            public void run() {
                ((OSCoapStack)coapstack).sendRequest(request, db);
            }
        });
    }
}
