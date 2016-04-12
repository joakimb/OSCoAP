package org.eclipse.californium.core.network.stack.objectsecurity;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.Endpoint;

import java.net.URI;

/**
 * Created by joakim on 12/04/16.
 */
public class OSCoapClient extends CoapClient {
    OSTidDB db;

    /**
     * Constructs a new CoapClient that has no destination URI yet.
     */
    public OSCoapClient(OSTidDB db) {
        super();
        this.db = db;
    }

    /**
     * Constructs a new CoapClient that sends requests to the specified URI.
     *
     * @param uri the uri
     */
    public OSCoapClient(String uri, OSTidDB db) {
        super(uri);
        this.db = db;
    }

    /**
     * Constructs a new CoapClient that sends request to the specified URI.
     *
     * @param uri the uri
     */
    public OSCoapClient(URI uri, OSTidDB db) {
        super(uri);
        this.db = db;
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
    public OSCoapClient(OSTidDB db, String scheme, String host, int port, String... path) {
        super(scheme, host, port, path);
        this.db = db;
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
        request.getOptions().addOption(new Option(OptionNumberRegistry.OBJECT_SECURITY));
        return super.send(request,outEndpoint);
    }

}
