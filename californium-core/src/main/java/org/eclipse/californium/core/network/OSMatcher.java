package org.eclipse.californium.core.network;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.stack.objectsecurity.CryptoContextDB;

/**
 * Created by joakim on 12/04/16.
 */
public class OSMatcher extends Matcher{

    private CryptoContextDB db;

    public OSMatcher(CryptoContextDB db, NetworkConfig config) {
        super(config);
        this.db = db;
    }

    @Override
    public Exchange receiveRequest(Request request) {
        Exchange exchange = super.receiveRequest(request);
        exchange.setCryptographicContextDB(db);
        return exchange;
    }
}
