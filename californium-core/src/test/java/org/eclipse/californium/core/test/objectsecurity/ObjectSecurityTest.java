package org.eclipse.californium.core.test.objectsecurity;

import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.*;
import org.eclipse.californium.core.coap.*;
import org.eclipse.californium.core.network.stack.objectsecurity.*;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSSequenceNumberException;
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
    CryptoContextDB serverDBA;
    CryptoContextDB clientDBA;

    /**
     * Sets up one CryptoContext database for a server and one for a client. Also sets up a ObjectSecuritylayer.
     */
    @Before
    public void setup() {
        System.out.println("\nStart "+getClass().getSimpleName());
        osLayer = new ObjectSecurityLayer();
        serverDBA = new HashMapCryptoContextDB();
        clientDBA = new HashMapCryptoContextDB();
        byte[] cidA = BigInteger.ONE.toByteArray();
        byte[] cidB = BigInteger.ONE.toByteArray();
        CryptoContext serverContextA = new CryptoContext(BigInteger.ONE);
        CryptoContext clientContextA = new CryptoContext(BigInteger.ONE);
        try {
            serverDBA.addContext(cidA, "coap://localhost/", serverContextA);
            clientDBA.addContext(cidB, "coap://localhost/", clientContextA);
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
     * Tests that the encrypted option is a valid CBOR object after encryption of message without payload.
     */
    @Test
    public void testEncryptedNoOptionsNoPayload(){
        Request request = Request.newGet().setURI("coap://localhost:5683");
		request.getOptions().addOption(new Option(OptionNumberRegistry.OBJECT_SECURITY));
        try {
                osLayer.prepareSend(request, clientDBA.getContext("coap://localhost:5683"));
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        } catch (OSSequenceNumberException e) {
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
        assertTrue(cbor.get("number").AsInt64() == OptionNumberRegistry.OBJECT_SECURITY);
    }


    /**
     * Tests that protected options are encrypted and moved to OSOption-value
     * after encryption and restored after decryption.
     */
    @Test
    public void testEncryptDecryptOptions(){
        Request request = Request.newGet().setURI("coap://localhost:5683");
        request.getOptions().setLocationPath("/test/path");
		request.getOptions().addOption(new Option(OptionNumberRegistry.OBJECT_SECURITY));
        assertEquals(2,request.getOptions().getLocationPathCount());
        try {
            osLayer.prepareSend(request, clientDBA.getContext("coap://localhost:5683"));
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        } catch (OSSequenceNumberException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        assertEquals(0,request.getOptions().getLocationPathCount());
        try {
            osLayer.prepareReceive(request, serverDBA);
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        } catch (OSSequenceNumberException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        assertEquals(2,request.getOptions().getLocationPathCount());
    }

    /**
     * Tests that message payload is replaced by object security option payload.
     */
    @Test
    public void testsEncryptDecryptPayloadInPayload(){
        Request request = Request.newPost().setURI("coap://localhost:5683");
		request.getOptions().addOption(new Option(OptionNumberRegistry.OBJECT_SECURITY));
        request.setPayload("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assertTrue("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".equals(request.getPayloadString()));
        try {
            osLayer.prepareSend(request, clientDBA.getContext("coap://localhost:5683"));
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        } catch (OSSequenceNumberException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        assertFalse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".equals(request.getPayloadString()));
        assertEquals("should be only 1 option (Object Security)", 1, request.getOptions().asSortedList().size());
        assertEquals("option payload not moved to message", 0, OptionJuggle.filterOSOption(request.getOptions()).getLength());
        try {
            osLayer.prepareReceive(request, serverDBA);
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        } catch (OSSequenceNumberException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        assertTrue("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".equals(request.getPayloadString()));
    }


    /**
     * Tests correct behaviour of sequence numbers.
     */
    @Test
    public void testSequenceNumbers(){
        CryptoContext clientCtx = null;
        CryptoContext serverCtx = null;
        try {
            clientCtx = clientDBA.getContext("coap://localhost/");
            serverCtx = serverDBA.getContext("coap://localhost/");
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        Request request1 = null;
        try {
            request1 = sendRequest("coap://localhost/",clientDBA);
            Request request2 = sendRequest("coap://localhost/",clientDBA);
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        } catch (OSSequenceNumberException e) {
            e.printStackTrace();
        }
        assertTrue("seq no:s incorrect",assertCtxState(clientCtx,2, 0));
        try {
            receiveRequest(request1, serverDBA);
            assertTrue("seq no:s incorrect",assertCtxState(serverCtx,0, 1));
            Response response1 = sendResponse("it is thursday, citizen", serverCtx);
            assertTrue("seq no:s incorrect",assertCtxState(serverCtx,1, 1));
            receiveResponse(response1, clientCtx);
            assertTrue("seq no:s incorrect",assertCtxState(clientCtx,2, 1));
        } catch (OSSequenceNumberException e) {
            e.printStackTrace();
            assertTrue(false);
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        }


    }




    @Test
    public void testSequenceNumbersReplayReject(){

        // Test Receive replay of request
        Request request = Request.newPost().setURI("coap://localhost:5683");
        Request request2 = Request.newPost().setURI("coap://localhost:5683");
        request.getOptions().addOption(new Option(OptionNumberRegistry.OBJECT_SECURITY));
        request2.getOptions().addOption(new Option(OptionNumberRegistry.OBJECT_SECURITY));
        try {
            //sending seq 1
            osLayer.prepareSend(request, clientDBA.getContext("coap://localhost:5683"));
            setup();// reset sequence number counters
            osLayer.prepareSend(request2, clientDBA.getContext("coap://localhost:5683"));
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        } catch (OSSequenceNumberException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        //receiving seq 1 twice
        boolean detectedDuplicate = false;
        try {
            osLayer.prepareReceive(request, serverDBA);
            osLayer.prepareReceive(request2, serverDBA);
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        } catch (OSSequenceNumberException e) {
            detectedDuplicate = true;
        }
        assertTrue(detectedDuplicate);

        //Test receive replay of response
        setup();// reset sequence number counters
        Response response = null;
        Response response2 = null;
        try {
            response = sendResponse("response", serverDBA.getContext("coap://localhost/"));
            setup();// reset sequence number counters
            response2 = sendResponse("response", serverDBA.getContext("coap://localhost/"));
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        } catch (OSSequenceNumberException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        detectedDuplicate = false;
        try {
            osLayer.prepareReceive(response, clientDBA.getContext("coap://localhost:5683"));
            osLayer.prepareReceive(response2, clientDBA.getContext("coap://localhost:5683"));
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        } catch (OSSequenceNumberException e) {
            detectedDuplicate = true;
        }
        assertTrue(detectedDuplicate);
    }

    @Test
    public void testSendSequenceNumberWrap() {
        try {
            clientDBA.getContext("coap://localhost:5683").setSeqMax(new BigInteger("2"));
        } catch (OSTIDException e) {
            e.printStackTrace();
        }

        //Test send
        Request req = null;
        try {
            sendRequest("coap://localhost:5683", clientDBA);
            req = sendRequest("coap://localhost:5683", clientDBA);
        } catch (OSTIDException e) {
            e.printStackTrace();
        } catch (OSSequenceNumberException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        boolean detectWrap = false;
        try {
            sendRequest("coap://localhost:5683", clientDBA);
        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        } catch (OSSequenceNumberException e) {
            detectWrap = true;
        }
        assertTrue(detectWrap);
    }

    @Test
    public void testReceiveSequenceNumberWrap() throws OSTIDException, OSSequenceNumberException {
        try {
            serverDBA.getContext("coap://localhost:5683").setSeqMax(new BigInteger("2"));
        } catch (OSTIDException e) {
            e.printStackTrace();
        }

        sendRequest("coap://localhost:5683", clientDBA);
        sendRequest("coap://localhost:5683", clientDBA);
        Request req = sendRequest("coap://localhost:5683", clientDBA);
        //Test receive
        boolean detectWrap = true;
        try {
            receiveRequest(req, serverDBA);
        } catch (OSSequenceNumberException e) {
            detectWrap = true;
        }
        assertTrue(detectWrap);
    }

    @Test
    public void testIV(){
        CryptoContext ctx;
        try {
            ctx = clientDBA.getContext("coap://localhost:5683");
            ctx.increaseSenderSeq();
            assertArrayEquals(new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ctx.getSenderIV());
            ctx.increaseSenderSeq();
            assertArrayEquals(new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03}, ctx.getSenderIV());
            for (int i = 2; i < 256; i++) ctx.increaseSenderSeq();
            assertArrayEquals(new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01}, ctx.getSenderIV());

            byte[] recSeq = new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
            assertArrayEquals(new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03}, ctx.getReceiverIV(recSeq));

        } catch (OSTIDException e) {
            e.printStackTrace();
            assertTrue(false);
        } catch (OSSequenceNumberException e) {
            e.printStackTrace();
            assertTrue(false);
        }


    }


    @Ignore
    @Test
    public void devtest(){
       //from californium examples
            OSCoapServer server = new OSCoapServer(serverDBA, 5683);
            server.add(new CoapResource("hello"){
                public void handleGET(CoapExchange exchange) {
                    exchange.respond(CoAP.ResponseCode.CONTENT, "Hi, there!");
                }
            });
            server.start();
        String uri = "coap://localhost:5683/hello?data=world";
        /*
            String uri2 = "coap://localhost:5685/hello?data=world";
         OSCoapServer server2 = new OSCoapServer(db, 5685);
            server2.add(new CoapResource("hello2"){
                public void handleGET(CoapExchange exchange) {
                    exchange.respond(CoAP.ResponseCode.CONTENT, "Hi, there!");
                }
            });
            server2.start();
*/
        OSCoapClient client = new OSCoapClient(uri, clientDBA);
 //       OSCoapClient client2 = new OSCoapClient(uri, db);
        CryptoContext tid = new CryptoContext(BigInteger.ONE);
        //CryptoContextDB db = HashMapCryptoContextDB.getDB();
        try {
            clientDBA.addContext(tid.getCid(), uri, tid);
            serverDBA.addContext(tid.getCid(), uri, tid);
        } catch (OSTIDException e) {
            e.printStackTrace();
            System.exit(1);
        }


        String content = client.get().getResponseText();

        //String content2 = client2.get().getResponseText();

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

    private boolean assertCtxState(CryptoContext ctx, int send, int receive){
        boolean equal = true;
        if (byteArrayToInt(ctx.getSenderSeq()) != send) equal = false;
        if (byteArrayToInt(ctx.getReceiverSeq()) != receive) equal = false;
        return equal;
    }

    private static int byteArrayToInt(byte[] b)
    {
        int value = 0;
        for (int i = 0; i < b.length; i++)
        {
            value = (value << 8) + (b[i] & 0xff);
        }
        return value;
    }

    private Request sendRequest(String uri, CryptoContextDB tidDB) throws OSTIDException, OSSequenceNumberException {
        CryptoContext tid = null;
        tid = tidDB.getContext(uri);
        Request request = Request.newPost().setURI("coap://localhost:5683");
        request.setType(CoAP.Type.CON);
        request.getOptions().addOption(new Option(OptionNumberRegistry.OBJECT_SECURITY));
        osLayer.prepareSend(request, tid);
        return request;
    }

    private Request receiveRequest(Request request, CryptoContextDB db) throws OSSequenceNumberException, OSTIDException {
        osLayer.prepareReceive(request, db);
        return request;
    }

    private Response receiveResponse(Response response, CryptoContext ctx) throws OSSequenceNumberException, OSTIDException {
        osLayer.prepareReceive(response, ctx);
        return response;
    }

    private Response sendResponse(String responsePayload, CryptoContext tid) throws OSTIDException, OSSequenceNumberException {

        Response response = null;

        if (responsePayload == null || responsePayload.length() <= 0){
            response = new Response(CoAP.ResponseCode.VALID);
        } else {
            response = new Response(CoAP.ResponseCode.CONTENT);
            response.setPayload(responsePayload);
		    response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
        }
        response.getOptions().addOption(new Option(OptionNumberRegistry.OBJECT_SECURITY));
        osLayer.prepareSend(response, tid);
        return response;
    }

}
