package org.eclipse.californium.core.test.objectsecurity;

import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.*;
import org.eclipse.californium.core.network.stack.objectsecurity.*;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

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
        db = OSHashMapTIDDB.getDB();
        byte[] cidA = BigInteger.ONE.toByteArray();
        byte[] cidB = (new BigInteger("2")).toByteArray();
        OSTid tidA = new OSTid(BigInteger.ONE);
        OSTid tidB = new OSTid(new BigInteger("2"));
        try {
            db.addTid(cidA, "coap://localhost/", tidA);
            //db.addTid(cidB, "coap://localhost/", tidB);
        } catch (OSTIDException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    @After
    public void tearDown() {
        System.out.println("End "+getClass().getSimpleName());
    }

    /**
     * Tests that the encrypted option is a valid CBOR object
     */
    @Test
    public void testEncryptedNoOptionsNoPayload(){
        Request request = Request.newGet().setURI("coap://localhost:5683");
        request.setType(CoAP.Type.CON);
		request.getOptions().addOption(new Option(OptionNumberRegistry.OBJECT_SECURITY));
        try {
                osLayer.prepareSend(request, db.getTID("coap://localhost:5683"));
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        System.out.println(request.getOptions().toString());
        CBORObject cbor = CBORObject.FromObject(OptionJuggle.filterOSOption(request.getOptions()));
        System.out.println(cbor.toString());
        System.out.println(cbor.getKeys());
        assertTrue(cbor.get("noCacheKey").isFalse());
        assertTrue(cbor.get("critical").isTrue());
        assertTrue(cbor.get("unSafe").isFalse());
        assertTrue(cbor.get("number").AsInt64() == 21);
    }

    /**
     * Tests that protected options are moved to OSOption-value
     */
    @Test
    public void testDecryptPayloadInOption(){
        Request request = Request.newGet().setURI("coap://localhost:5683");
        request.setType(CoAP.Type.CON);
        request.getOptions().setLocationPath("/test/path");
		request.getOptions().addOption(new Option(OptionNumberRegistry.OBJECT_SECURITY));
        assertEquals(2,request.getOptions().getLocationPathCount());
        try {
            osLayer.prepareSend(request, db.getTID("coap://localhost:5683"));
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        assertEquals(0,request.getOptions().getLocationPathCount());
        try {
            osLayer.prepareReceive(request);
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        assertEquals(2,request.getOptions().getLocationPathCount());
    }

    @Test
    public void testDecryptPayloadInPayload(){
        Request request = Request.newPost().setURI("coap://localhost:5683");
        request.setType(CoAP.Type.CON);
		request.getOptions().addOption(new Option(OptionNumberRegistry.OBJECT_SECURITY));
        request.setPayload("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assertTrue("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".equals(request.getPayloadString()));
        try {
            osLayer.prepareSend(request, db.getTID("coap://localhost:5683"));
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        assertFalse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".equals(request.getPayloadString()));
        try {
            osLayer.prepareReceive(request);
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        assertTrue("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".equals(request.getPayloadString()));
    }

    @Test
    public void testOptionsMovedToOSOption(){
        //also test proxy-uri censoring
    }

    @Test
    public void testSequenceNumbersIncreasing(){
        List<Request> requests = new ArrayList<>();
        for (int i  = 0; i < 100; i++){
            Request request = Request.newPost().setURI("coap://localhost:5683");
            request.setType(CoAP.Type.CON);
		    request.getOptions().addOption(new Option(OptionNumberRegistry.OBJECT_SECURITY));
            requests.add(request);
        }
        int clientSeq = 0;
        for (Request request : requests) {
            try {
                osLayer.prepareSend(request, db.getTID("coap://localhost:5683"));
            } catch (OSTIDException e) {
                e.printStackTrace();
                assertTrue(false);
            }
            try {
                osLayer.prepareReceive(request);
            } catch (OSTIDException e) {
                e.printStackTrace();
                assertTrue(false);
            }
            clientSeq++;
        }

        try{
            assertArrayEquals("senderSeq not correct", (new BigInteger(String.valueOf(clientSeq))).toByteArray(), db.getTID("coap://localhost:5683").getSenderSeq());
            assertArrayEquals("receiverSeq not correct", (new BigInteger(String.valueOf(clientSeq))).toByteArray(), db.getTID("coap://localhost:5683").getSenderSeq());
        } catch (Exception e){
            e.printStackTrace();
            assertTrue(false);
        }
    }

    private byte[] sendRequest(String uri, OSTidDB tidDB) {
        OSTid tid = null;
        try {
            tid = tidDB.getTID(uri);
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        Request request = Request.newPost().setURI("coap://localhost:5683");
        request.setType(CoAP.Type.CON);
        request.getOptions().addOption(new Option(OptionNumberRegistry.OBJECT_SECURITY));
        try {
            osLayer.prepareSend(request, tid);
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        return tid.getCid();
    }

    private Request receiveRequest(Request request){
        try {
            osLayer.prepareReceive(request);
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        return request;
    }

    private Response sendResponse(Request request, String responsePayload, OSTid tid){

        Response response = null;

        if (responsePayload == null || responsePayload.length() <= 0){
            response = new Response(CoAP.ResponseCode.VALID);
        } else {
            response = new Response(CoAP.ResponseCode.CONTENT);
            response.setPayload(responsePayload);
		    response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
        }
        try {
            osLayer.prepareSend(response, tid);
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        return response;
    }


    @Test
    public void testSequenceNumbersReplayReject(){
        Request request = Request.newPost().setURI("coap://localhost:5683");
        request.setType(CoAP.Type.CON);
        request.getOptions().addOption(new Option(OptionNumberRegistry.OBJECT_SECURITY));
        try {
            //sending seq 1
            osLayer.prepareSend(request, db.getTID("coap://localhost:5683"));
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        //receiving seq 1
        try {
            osLayer.prepareReceive(request);
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        }


    }

    @Ignore
    @Test
    public void devtest(){
       //from californium examples
            CoapServer server = new CoapServer(5683);
            server.add(new CoapResource("hello"){
                public void handleGET(CoapExchange exchange) {
                    exchange.respond(CoAP.ResponseCode.CONTENT, "Hi, there!");
                }
            });
            server.start();
        String uri = "coap://localhost:5683/hello?data=world";
            String uri2 = "coap://localhost:5685/hello?data=world";
         CoapServer server2 = new CoapServer(5685);
            server2.add(new CoapResource("hello2"){
                public void handleGET(CoapExchange exchange) {
                    exchange.respond(CoAP.ResponseCode.CONTENT, "Hi, there!");
                }
            });
            server2.start();

        CoapClient client = new CoapClient(uri);
        CoapClient client2 = new CoapClient(uri);
            client.useObjectSecurity();
        OSTid tid = new OSTid(BigInteger.ONE);
        OSTidDB db = OSHashMapTIDDB.getDB();
        try {
            db.addTid(tid.getCid(), uri, tid);
        } catch (OSTIDException e) {
            e.printStackTrace();
            System.exit(1);
        }


        String content = client.get().getResponseText();

        String content2 = client2.get().getResponseText();

            System.out.println("RESPONSE: " + content);
        //assertArrayEquals(content, new byte[4]);
    }

    @Ignore
    @Test
    public void tmpBorderRouterTest(){

            CoapClient client = new CoapClient("coap://[aaaa::212:4b00:40f:b80]:5683/test/hello");

            String content = client.get().getResponseText();

            System.out.println("RESPONSE from chip: " + content);
    }

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
