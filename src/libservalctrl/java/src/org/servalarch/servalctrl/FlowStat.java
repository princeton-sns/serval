package org.servalarch.servalctrl;

public class FlowStat {
    public long flowId;
    int protocol;
    public long inode;

    public long totPktsSent;
    public long totBytesSent;
    
    public long totPktsRecv;
    public long totBytesRecv;
    
    public long dPktsSent;
    public long dBytesSent;
    
    public long dPktsRecv;
    public long dBytesRecv;

    public FlowStat(long flowId, int protocol, long inode, long pktsSent, 
                    long bytesSent, long pktsRecv, long bytesRecv) {
        this.flowId = flowId;
        this.protocol = protocol;
        this.inode = inode;
        
        this.totPktsSent = pktsSent;
        this.totBytesSent = bytesSent;
        
        this.totPktsRecv = pktsRecv;
        this.totBytesRecv = bytesRecv;
    }

    public int getProtocol() {
        return protocol;
    }

    public long pktsSent() {
        return totPktsSent;
    }
}
