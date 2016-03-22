package org.eclipse.californium.core.test.objectsecurity;

import com.upokecenter.cbor.CBORObject;
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
        db.addTid(cidA, tidA);
        db.addTid(cidB, tidB);
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
		request.getOptions().addOption(new ObjectSecurityOption());
        osLayer.prepareSend(request, request.getCode().value);
        System.out.println(request.getOptions().toString());
        CBORObject cbor = CBORObject.FromObject(osLayer.filterOSOption(request.getOptions()));
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
		request.getOptions().addOption(new ObjectSecurityOption());
        assertEquals(2,request.getOptions().getLocationPathCount());
        osLayer.prepareSend(request, request.getCode().value);
        assertEquals(0,request.getOptions().getLocationPathCount());
        osLayer.prepareReceive(request, request.getCode().value);
        assertEquals(2,request.getOptions().getLocationPathCount());
    }

    @Test
    public void testDecryptPayloadInPayload(){
        Request request = Request.newPost().setURI("coap://localhost:5683");
        request.setType(CoAP.Type.CON);
		request.getOptions().addOption(new ObjectSecurityOption());
        request.setPayload("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assertTrue("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".equals(request.getPayloadString()));
        osLayer.prepareSend(request, request.getCode().value);
        assertFalse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".equals(request.getPayloadString()));
        osLayer.prepareReceive(request, request.getCode().value);
        assertTrue("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".equals(request.getPayloadString()));
    }

    @Test
    public void testOptionsMovedToOSOption(){
        //also test proxy-uri censoring
    }

    @Test
    public void testSequenceNumbers(){
        assertTrue(true);
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
