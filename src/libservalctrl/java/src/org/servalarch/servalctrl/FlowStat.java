package org.servalarch.servalctrl;

public class FlowStat {
    public long flowId;
    int protocol;

    public long pktsSent;

    public FlowStat(long flowId, int protocol, long pktsSent) {
        this.flowId = flowId;
        this.protocol = protocol;
        this.pktsSent = pktsSent;
    }

    public int getProtocol() {
        return protocol;
    }

    public long pktsSent() {
        return pktsSent;
    }
}
