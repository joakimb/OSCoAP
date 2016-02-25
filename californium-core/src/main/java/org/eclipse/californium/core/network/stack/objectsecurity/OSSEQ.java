package org.eclipse.californium.core.network.stack.objectsecurity;

import org.eclipse.californium.core.network.serialization.DatagramWriter;

/**
 * Created by joakim on 2016-02-25.
 */
public class OSSEQ {

    private int seq;

    public OSSEQ(int seq){
        this.seq = seq;
    }

    public OSSEQ(){
        this.seq = 0;
    }

    public byte[] serialise(){
        DatagramWriter writer = new DatagramWriter();
        writer.write(seq,24);
        return writer.toByteArray();
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof OSSEQ)) return false;
        OSSEQ other = (OSSEQ) o;
        return this.seq == other.seq;
    }
}
