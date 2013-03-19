package org.servalarch.servalctrl;

public class FlowTCPStat extends FlowStat {

	public long retrans;
	public long lost;
	public long rtt;
	public long rttvar;
	public long mss;

	public long snd_wnd;
	public long snd_cwnd;
	public long snd_ssthresh;
	public long snd_una;
	public long snd_nxt;
	
	public long rcv_wnd;
	public long rcv_nxt;

	public FlowTCPStat(long flowId, int protocol, long inode, long pktsSent, long bytesSent, 
			long pktsRecv, long bytesRecv, long retrans, long lost, long rtt, 
			long rttvar, long mss, long snd_wnd, long snd_cwnd, long snd_ssthresh, long snd_una, 
			long snd_nxt, long rcv_wnd, long rcv_nxt) {
		super(flowId, protocol, inode, pktsSent, bytesSent, pktsRecv, bytesRecv);
		this.retrans = retrans;
		this.lost = lost;
		this.rtt = rtt;
		this.rttvar = rttvar;
		this.mss = mss;
		
		this.snd_wnd = snd_wnd;
		this.snd_cwnd = snd_cwnd;
		this.snd_ssthresh = snd_ssthresh;
		this.snd_una = snd_una;
		this.snd_nxt = snd_nxt;
	
		this.rcv_wnd = rcv_wnd;
		this.rcv_nxt = rcv_nxt;
	}
	
	public long unacked() {
		if (snd_nxt < snd_una) {
			return snd_nxt + (0x0000FFFF - snd_una);
		}
		else {
			return snd_nxt - snd_una;
		}
	}

	@Override
	public String toString() {
		return String.format("{pktsSent: %d, bytesSent: %d, pktsRecv: %d, bytesRecv: %d, retrans: %d, lost: %d, " +
				"rtt: %d, rttvar: %d, mss: %d, snd_wnd: %d, snd_cwnd: %d, snd_ssthresh: %d, snd_una: %d, snd_nxt: %d, " +
				"rcv_wnd: %d, rcv_nxt: %d}", totPktsSent, totBytesSent, totPktsRecv, totBytesRecv, retrans, lost, rtt, 
				rttvar, mss, snd_wnd, snd_cwnd, snd_ssthresh, snd_una, snd_nxt, rcv_wnd, rcv_nxt);
	}
}
