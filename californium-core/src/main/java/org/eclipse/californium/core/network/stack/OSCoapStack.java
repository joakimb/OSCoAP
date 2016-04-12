package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.stack.objectsecurity.CryptoContextDB;
import org.eclipse.californium.core.network.stack.objectsecurity.ObjectSecurityLayer;

/**
 * Created by joakim on 12/04/16.
 */
public class OSCoapStack extends CoapStack{

    public OSCoapStack(NetworkConfig config, Outbox outbox){
        this.top = new OSStackTopAdapter();
        this.outbox = outbox;

        ReliabilityLayer reliabilityLayer;
        if (config.getBoolean(NetworkConfig.Keys.USE_CONGESTION_CONTROL) == true) {
            reliabilityLayer = CongestionControlLayer.newImplementation(config);
            LOGGER.config("Enabling congestion control: " + reliabilityLayer.getClass().getSimpleName());
        } else {
            reliabilityLayer = new ReliabilityLayer(config);
        }

        this.layers =
                new Layer.TopDownBuilder()
                        .add(top)
                        .add(new ObserveLayer(config))
                        .add(new BlockwiseLayer(config))
                        .add(reliabilityLayer)
                        .add(new ObjectSecurityLayer())
                        .add(bottom = new StackBottomAdapter())
                        .create();

        // make sure the endpoint sets a MessageDeliverer
    }

    public void sendRequest(Request request, CryptoContextDB db) {
        ((OSStackTopAdapter)top).sendRequest(request, db);
    }

    protected class OSStackTopAdapter extends CoapStack.StackTopAdapter{

        public void sendRequest(Request request, CryptoContextDB db) {
            Exchange exchange = new Exchange(request, Exchange.Origin.LOCAL);
            exchange.setCryptographicContextDB(db);
            sendRequest(exchange, request); // layer method
        }
    }
}
