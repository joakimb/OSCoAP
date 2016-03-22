package org.eclipse.californium.core.test.objectsecurity;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.stack.objectsecurity.*;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

/**
 * Created by joakim on 2016-02-11.
 */
public class ObjectSecurityTest {

    ObjectSecurityLayer osLayer;
    OSTidDB db;
    @Before
    public void setup() {
        System.out.println("\nStart "+getClass().getSimpleName());
        osLayer = new ObjectSecurityLayer();
        db = new OSHashMapTIDDB();
        byte[] cidA = BigInteger.ONE.toByteArray();
        byte[] cidB = (new BigInteger("2")).toByteArray();
        OSTid tidA = new OSTid(BigInteger.ONE);
        OSTid tidB = new OSTid(new BigInteger("2"));
        db.addTid(cidA, tidA);
        db.addTid(cidB, tidB);
    }

    @After
    public void tearDown() {
        System.out.println("End "+getClass().getSimpleName());
    }

    @Test
    public void testEncryptedNoOptionsNoPayload(){
        /*
        Request request = Request.newGet().setURI("coap://localhost:5683");
        request.setType(CoAP.Type.CON);
		request.getOptions().addOption(new ObjectSecurityOption());
        osLayer.prepareSend(request, request.getCode().value);
        System.out.println(request.getOptions().toString());
        */
    }


    @Ignore
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
            client.useObjectSecurity();
        OSTid tid = new OSTid(BigInteger.ONE);
        OSTidDB db = OSHashMapTIDDB.getDB();
        db.addTid(tid.getCid(),tid);


            String content = client.get().getResponseText();

            System.out.println("RESPONSE: " + content);
        //assertArrayEquals(content, new byte[4]);
            System.exit(0);
    }
/*
    @Test
    public void tmpTest(){
        //int[] msg = {0x84,  0x43,  0xa1,  0x01,  0x05,  0xa0,  0x58,  0x1b,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x01,  0x00,  0x00,  0x00,  0x40,  0x01,  0xb6,  0x65,  0x78,  0x6a,  0x6f,  0x62,  0x62,  0x06,  0x73,  0x65,  0x63,  0x75,  0x72,  0x65,  0x58,  0x20,  0x41,  0x9c,  0x92,  0xf7,  0x2e,  0x38,  0x78,  0x4a,  0x4a,  0x50,  0x90,  0xa6,  0xcc,  0x08,  0xf6,  0xbb,  0x31,  0x78,  0x2a,  0x9d,  0xb4,  0xba,  0xcf,  0x2d,  0xbc,  0x93,  0x23,  0xf6,  0x62,  0x6a,  0xa9,  0x0e};
       int[] msg = {0x84,  0x43,  0xa1,  0x01,  0x04,  0xa0,  0x58,  0x1b,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x01,  0x00,  0x00,  0x00,  0x40,  0x01,  0xb6,  0x65,  0x78,  0x6a,  0x6f,  0x62,  0x62,  0x06,  0x73,  0x65,  0x63,  0x75,  0x72,  0x65,  0x48,  0x3b,  0xcc,  0x72,  0x1d,  0x1f,  0xcc,  0x46,  0xf6};
        OSTid tid = new OSTid(BigInteger.ONE);
        byte bytemsg[] = new byte[msg.length];

        for (int i = 0; i < msg.length; i++){
           bytemsg[i] = (byte)msg[i];
        }

        boolean test = ObjectSecurityOption.isValidMAC0(bytemsg, tid);
        assertTrue(test);
        System.out.println("rtest" + test);
    }
*/
    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }


}
