package org.eclipse.californium.core.test;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

/**
 * Created by joakim on 2016-02-11.
 */
public class ObjectSecurityTest {

    @Before
    public void setupServer() {
        System.out.println("\nStart "+getClass().getSimpleName());
    }

    @After
    public void shutdownServer() {
        System.out.println("End "+getClass().getSimpleName());
    }

    @Test
    public void devTest(){

        //from californium examples
            CoapServer server = new CoapServer(5683);
            server.add(new CoapResource("hello"){
                public void handleGET(CoapExchange exchange) {
                    exchange.respond(CoAP.ResponseCode.CONTENT, "Hi, there!");
                }
            });
            server.start();

            CoapClient client = new CoapClient("coap://localhost:5683/hello?data=world");


            String content = client.get().getResponseText();
            System.out.println("RESPONSE: " + content);
        //assertArrayEquals(content, new byte[4]);
            System.exit(0);
    }


}
