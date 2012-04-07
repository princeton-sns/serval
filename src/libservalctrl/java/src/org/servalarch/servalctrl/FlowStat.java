package org.servalarch.servalctrl;

public class FlowStat {
    public long flowId;
    int protocol;

    public long pktsSent;
    public long bytesSent;
    
    public long pktsRecv;
    public long bytesRecv;

    public FlowStat(long flowId, int protocol, long pktsSent, long bytesSent,
    		long pktsRecv, long bytesRecv) {
        this.flowId = flowId;
        this.protocol = protocol;
        
        this.pktsSent = pktsSent;
        this.bytesSent = bytesSent;
        
        this.pktsRecv = pktsRecv;
        this.bytesRecv = bytesRecv;
    }

    public int getProtocol() {
        return protocol;
    }

    public long pktsSent() {
        return pktsSent;
    }
}
