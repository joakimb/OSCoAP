package org.eclipse.californium.core;

import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.OSCoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.stack.objectsecurity.CryptoContextDB;
import org.eclipse.californium.core.server.ServerMessageDeliverer;
import org.eclipse.californium.core.server.resources.DiscoveryResource;

import java.util.ArrayList;
import java.util.concurrent.Executors;

/**
 * Created by joakim on 12/04/16.
 */
public class OSCoapServer extends CoapServer{

    /**
     * Constructs a default server. The server starts after the method
     * {@link #start()} is called. If a server starts and has no specific ports
     * assigned, it will bind to CoAp's default port 5683.
     */
    public OSCoapServer(CryptoContextDB db) {

        this(db, NetworkConfig.getStandard());
    }

    /**
     * Constructs a server that listens to the specified port(s) after method
     * {@link #start()} is called.
     *
     * @param ports the ports to bind to
     */
    public OSCoapServer(CryptoContextDB db, int... ports) {
        this(db, NetworkConfig.getStandard(), ports);
    }

    /**
     * Constructs a server with the specified configuration that listens to the
     * specified ports after method {@link #start()} is called.
     *
     * @param config the configuration, if <code>null</code> the configuration returned by
     * {@link NetworkConfig#getStandard()} is used.
     * @param ports the ports to bind to
     */
    public OSCoapServer(CryptoContextDB db, NetworkConfig config, int... ports) {

        super(config,ports);
        // endpoints
        this.endpoints = new ArrayList<Endpoint>();

        // create endpoint for each port
        for (int port:ports)
            addEndpoint(new OSCoapEndpoint(db, port, config));
    }
}
