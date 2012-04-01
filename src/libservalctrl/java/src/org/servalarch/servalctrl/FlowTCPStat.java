package org.servalarch.servalctrl;

public class FlowTCPStat extends FlowStat {

    public FlowTCPStat(long flowId, int protocol, long pktsSent) {
        super(flowId, protocol, pktsSent);
    }
}
