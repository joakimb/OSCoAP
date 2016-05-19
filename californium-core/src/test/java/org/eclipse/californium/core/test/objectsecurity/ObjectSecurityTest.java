package org.eclipse.californium.core.test.objectsecurity;

import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.*;
import org.eclipse.californium.core.coap.*;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.stack.objectsecurity.*;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSSequenceNumberException;
import org.eclipse.californium.core.network.stack.objectsecurity.osexcepitons.OSTIDException;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.InMemoryPskStore;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import static org.bouncycastle.crypto.tls.ConnectionEnd.server;
import static org.junit.Assert.*;

/**
 * Created by joakim on 2016-02-11.
 */
public class ObjectSecurityTest {

    ObjectSecurityLayer osLayer;
    CryptoContextDB serverDBA;
    CryptoContextDB clientDBA;
    BigInteger cid_bi;

    /**
     * Sets up one CryptoContext database for a server and one for a client. Also sets up a ObjectSecuritylayer.
     */
    @Before
    public void setup() {
        System.out.println("\nStart "+getClass().getSimpleName());
        osLayer = new ObjectSecurityLayer();
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
        assertEquals("should be only 2 options (Object Security and max age)", 2, request.getOptions().asSortedList().size());
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
    public void compatibilityTest(){

         OSCoapServer server = new OSCoapServer(serverDBA, 5683);
            server.add(new CoapResource("hello"){
                public void handleGET(CoapExchange exchange) {
                    exchange.respond(CoAP.ResponseCode.CONTENT, "Hi, there!");
                }
            });
            server.start();
        String uri = "coap://[aaaa::212:4b00:40f:b80]:5683/test/hello";
        //String uri = "coap://localhost/hello";

        OSCoapClient client = new OSCoapClient(uri, clientDBA);
        CryptoContext tidc = clientDBA.getContext(cid_bi.toByteArray());
        try {
            clientDBA.addContext(tidc.getCid(), uri, tidc);
        } catch (OSTIDException e) {
            e.printStackTrace();
            System.exit(1);
        }

        String content = client.get().getResponseText();

        System.out.println("RESPONSE: " + content);
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
        //CryptoContext tid = new CryptoContext(BigInteger.ONE);
        //CryptoContextDB db = HashMapCryptoContextDB.getDB();
        CryptoContext tidc = clientDBA.getContext(cid_bi.toByteArray());
        CryptoContext tids = serverDBA.getContext(cid_bi.toByteArray());
        try {
            clientDBA.addContext(tidc.getCid(), uri, tidc);
            serverDBA.addContext(tids.getCid(), uri, tids);
        } catch (OSTIDException e) {
            e.printStackTrace();
            System.exit(1);
        }


        String content = client.get().getResponseText();

        //String content2 = client2.get().getResponseText();

            System.out.println("RESPONSE: " + content);
        //assertArrayEquals(content, new byte[4]);
    }

    private static String payload = "aaaaa";                        //5
    //private static String payload = "aaaaaaaaaa";                   //10
    //private static String payload = "aaaaaaaaaaaaaaa";              //15
    //private static String payload = "aaaaaaaaaaaaaaaaaaaa"          //20
    //private static String payload = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";     //40
    //private static String payload = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";//80

    @Ignore
    @Test
    public void testOSCoAP_single_req_resp(){
        OSCoapServer server = new OSCoapServer(serverDBA, 5683);
        server.add(new CoapResource("t"){
            public void handleGET(CoapExchange exchange) {
                exchange.respond(CoAP.ResponseCode.CONTENT, payload);
            }
        });
        server.start();
        String uri = "coap://localhost:5683/t?";
        OSCoapClient client = new OSCoapClient(uri, clientDBA);
        CryptoContext tidc = clientDBA.getContext(BigInteger.ONE.toByteArray());
        CryptoContext tids = serverDBA.getContext(BigInteger.ONE.toByteArray());
        try {
            clientDBA.addContext(tidc.getCid(), uri, tidc);
            serverDBA.addContext(tids.getCid(), uri, tids);
        } catch (OSTIDException e) {
            e.printStackTrace();
            System.exit(1);
        }

        String content = client.get().getResponseText();

        System.out.println("RESPONSE: " + content);
    }

    @Ignore
    @Test
    public void test_plain_CoAP_single_req_resp(){
        CoapServer server = new CoapServer(5683);
        server.add(new CoapResource("t"){
            public void handleGET(CoapExchange exchange) {
                exchange.respond(CoAP.ResponseCode.CONTENT, payload);
            }
        });
        server.start();
        String uri = "coap://localhost:5683/t?";
        CoapClient client = new CoapClient(uri);

        String content = client.get().getResponseText();

        System.out.println("RESPONSE: " + content);
    }

    public static final int DTLS_PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_SECURE_PORT);
    @Ignore
    @Test
    public void test_CoAP_DTLS_single_req_resp(){

//        ScandiumLogger.initialize();
        //ScandiumLogger.setLevel(Level.FINE);

        //============================ SERVER ========================================
        CoapServer server = new CoapServer();
        server.add(new CoapResource("t"){
            public void handleGET(CoapExchange exchange) {
                exchange.respond(CoAP.ResponseCode.CONTENT, payload);
            }
        });

        // Pre-shared secrets


        DtlsConnectorConfig.Builder serverConfig = new DtlsConnectorConfig.Builder(new InetSocketAddress(DTLS_PORT));
        serverConfig.setSupportedCipherSuites(new CipherSuite[]{CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
        serverConfig.setPskStore(new StaticPskStore("C", "secretPSK".getBytes()));

        DTLSConnector serverConnector = new DTLSConnector(serverConfig.build());

        server.addEndpoint(new CoapEndpoint(serverConnector, NetworkConfig.getStandard()));
        server.start();


        //=========================== CLIENT ============================================

        String uri = "coaps://localhost/t?";

        // Pre-shared secrets

        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(0));
        builder.setPskStore(new StaticPskStore("C", "secretPSK".getBytes()));
        builder.setSupportedCipherSuites(new CipherSuite[]{CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
        DTLSConnector dtlsConnector;
        dtlsConnector = new DTLSConnector(builder.build());

        CoapClient client = new CoapClient(uri);
        client.setEndpoint(new CoapEndpoint(dtlsConnector, NetworkConfig.getStandard()));
        CoapResponse response = client.get();
        server.stop();

        System.out.println("RESPONSE: " + response.getResponseText());
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
