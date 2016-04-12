package org.eclipse.californium.core.network;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.stack.OSCoapStack;
import org.eclipse.californium.core.network.stack.objectsecurity.CryptoContextDB;

/**
 * Created by joakim on 12/04/16.
 */
public class OSCoapEndpoint extends CoapEndpoint{

    public OSCoapEndpoint() {
        super();
        this.coapstack = new OSCoapStack(config, new OutboxImpl());
    }

    public void sendRequest(final Request request, final CryptoContextDB db) {
        // always use endpoint executor
        runInProtocolStage(new Runnable() {
            public void run() {
                ((OSCoapStack)coapstack).sendRequest(request, db);
            }
        });
    }
}
