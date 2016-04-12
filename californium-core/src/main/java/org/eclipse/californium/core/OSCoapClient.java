package org.eclipse.californium.core;

import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.OSCoapEndpoint;
import org.eclipse.californium.core.network.stack.objectsecurity.CryptoContextDB;

import java.io.IOException;
import java.net.URI;

/**
 * Created by joakim on 12/04/16.
 */
public class OSCoapClient extends CoapClient {
    CryptoContextDB db;

    private OSCoapEndpoint newEndpoint(){
        OSCoapEndpoint ep = new OSCoapEndpoint();

        try {
            ep.start();
        } catch (IOException e) {
            System.out.println("Could not create endpoint");
        }
        return ep;
    }

    /**
     * Constructs a new CoapClient that has no destination URI yet.
     */
    public OSCoapClient(CryptoContextDB db) {
        super();
        this.db = db;
        setEndpoint(newEndpoint());
    }

    /**
     * Constructs a new CoapClient that sends requests to the specified URI.
     *
     * @param uri the uri
     */
    public OSCoapClient(String uri, CryptoContextDB db) {
        super(uri);
        this.db = db;
        setEndpoint(newEndpoint());
    }

    /**
     * Constructs a new CoapClient that sends request to the specified URI.
     *
     * @param uri the uri
     */
    public OSCoapClient(URI uri, CryptoContextDB db) {
        super(uri);
        this.db = db;
        setEndpoint(newEndpoint());
    }

    /**
     * Constructs a new CoapClient with the specified scheme, host, port and
     * path as URI.
     *
     * @param scheme the scheme
     * @param host the host
     * @param port the port
     * @param path the path
     */
    public OSCoapClient(CryptoContextDB db, String scheme, String host, int port, String... path) {
        super(scheme, host, port, path);
        this.db = db;
        setEndpoint(newEndpoint());
    }


    /**
     * Sends the specified request over the specified endpoint.
     *
     * @param request the request
     * @param outEndpoint the endpoint
     * @return the request
     */
    @Override
    protected Request send(Request request, Endpoint outEndpoint) {
        OSCoapEndpoint ep = (OSCoapEndpoint) outEndpoint;

        request.getOptions().addOption(new Option(OptionNumberRegistry.OBJECT_SECURITY));
        // use the specified message type
        request.setType(super.type);

        if (blockwise!=0) {
            request.getOptions().setBlock2(new BlockOption(BlockOption.size2Szx(this.blockwise), false, 0));
        }

        ep.sendRequest(request, db);
        return request;
    }

}
