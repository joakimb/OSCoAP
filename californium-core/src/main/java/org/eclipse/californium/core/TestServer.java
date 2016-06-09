package org.eclipse.californium.core;

/**
 * Created by jakobfolkesson on 2016-05-25.
 */

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.stack.objectsecurity.CryptoContext;
import org.eclipse.californium.core.network.stack.objectsecurity.CryptoContextDB;
import org.eclipse.californium.core.network.stack.objectsecurity.HashMapCryptoContextDB;
import org.eclipse.californium.core.network.stack.objectsecurity.ObjectSecurityLayer;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;
import org.eclipse.californium.core.server.resources.CoapExchange;

import java.math.BigInteger;


import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.stack.objectsecurity.CryptoContext;
import org.eclipse.californium.core.network.stack.objectsecurity.CryptoContextDB;
import org.eclipse.californium.core.network.stack.objectsecurity.HashMapCryptoContextDB;
import org.eclipse.californium.core.network.stack.objectsecurity.ObjectSecurityLayer;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;
import org.eclipse.californium.core.server.resources.CoapExchange;

import java.math.BigInteger;

/**
 * Created by joakim on 2016-05-19.
 */
public class TestServer {
    public static void main(String[] args){
        ObjectSecurityLayer osLayer = new ObjectSecurityLayer();
        CryptoContextDB serverDBA;
        CryptoContextDB clientDBA;
        BigInteger cid_bi;

        serverDBA = new HashMapCryptoContextDB();
        clientDBA = new HashMapCryptoContextDB();
        byte[] saltClient = {0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47};
        byte[] keyClient = {0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 };
        cid_bi = new BigInteger("2");
        byte[] cidA = cid_bi.toByteArray();
        //byte[] saltClient = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
        byte[] saltServer = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
        //byte[] keyClient = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
        byte[] keyServer = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
        CryptoContext clientContextA = new CryptoContext(cid_bi, saltClient, saltServer, keyClient, keyServer);
        CryptoContext serverContextA = new CryptoContext(cid_bi, saltServer, saltClient, keyServer, keyClient);
        try {
            clientDBA.addContext(cidA, "coap://localhost/", clientContextA);
            serverDBA.addContext(cidA, "coap://localhost/", serverContextA);
        } catch (OSTIDException e) {
            e.printStackTrace();
            System.exit(1);
        }
        OSCoapServer server = new OSCoapServer(serverDBA, 5684);
        server.add(new CoapResource("hello"){
            public void handleGET(CoapExchange exchange) {
                System.out.println("GET inbound");
                exchange.respond(CoAP.ResponseCode.CONTENT, "Hi, there!");
            }
        });
        server.start();


    }
}

