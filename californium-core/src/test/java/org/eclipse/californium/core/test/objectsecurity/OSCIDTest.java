package org.eclipse.californium.core.test.objectsecurity;

import static org.junit.Assert.*;

import org.eclipse.californium.core.network.stack.objectsecurity.OSCID;
import org.junit.Test;

/**
 * Created by joakim on 2016-02-24.
 */
public class OSCIDTest {
    @Test
    public void testSerialise(){
        OSCID cid = new OSCID(21845,15,0); // 0x0101010101010101, 0x00001111, 0x00000000
        byte[] expected = {0x55,0x55,0x0F,0x00};
        assertArrayEquals(cid.serialise(),expected);
    }

    @Test
    public void testEquals(){
        OSCID cid1 = new OSCID(21845,15,0);
        OSCID cid2 = new OSCID(21845,15,0);
        OSCID cid3 = new OSCID(31845,15,0);
        OSCID cid4 = new OSCID(21845,16,0);
        OSCID cid5 = new OSCID(21845,15,1);
        assertEquals(cid1,cid2);
        assertNotEquals(cid1,cid3);
        assertNotEquals(cid1,cid4);
        assertNotEquals(cid1,cid5);
    }
}
