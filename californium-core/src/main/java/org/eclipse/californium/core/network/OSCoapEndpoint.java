package org.eclipse.californium.core.network;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.stack.OSCoapStack;
import org.eclipse.californium.core.network.stack.objectsecurity.CryptoContextDB;

import java.net.InetSocketAddress;

/**
 * Created by joakim on 12/04/16.
 */
public class OSCoapEndpoint extends CoapEndpoint{

    public OSCoapEndpoint() {
        super();
        this.coapstack = new OSCoapStack(config, new OutboxImpl());
    }

    /**
     * Instantiates a new endpoint with the specified port and configuration.
     *
     * @param port the UDP port
     * @param config the network configuration
     */
    public OSCoapEndpoint(CryptoContextDB db, int port, NetworkConfig config) {
        super(new InetSocketAddress(port), config);
        this.matcher = new OSMatcher(db, config);
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
