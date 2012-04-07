package org.servalarch.servalctrl;

public class FlowTCPStat extends FlowStat {

	public long retrans;
	public long lost;
	public long rtt;
	public long rttvar;
	public long mss;

	public long snd_cwnd;
	public long snd_ssthresh;
	public long snd_una;
	public long snd_nxt;
	
	public long rwnd;

	public FlowTCPStat(long flowId, int protocol, long pktsSent, long bytesSent, 
			long pktsRecv, long bytesRecv, long retrans, long lost, long rtt, 
			long rttvar, long mss, long snd_cwnd, long snd_ssthresh, long snd_una, long snd_nxt, long rwnd) {
		super(flowId, protocol, pktsSent, bytesSent, pktsRecv, bytesRecv);
		this.retrans = retrans;
		this.lost = lost;
		this.rtt = rtt;
		this.rttvar = rttvar;
		this.mss = mss;
		
		this.snd_cwnd = snd_cwnd;
		this.snd_ssthresh = snd_ssthresh;
		this.snd_una = snd_una;
		this.snd_nxt = snd_nxt;
	
		this.rwnd = rwnd;
	}

	@Override
	public String toString() {
		return String.format("{pktsSent: %d, bytesSent: %d, pktsRecv: %d, bytesRecv: %d, retrans: %d, lost: %d, " +
				"rtt: %d, rttvar: %d, mss: %d, snd_cwnd: %d, snd_ssthresh: %d, snd_una: %d, snd_nxt: %d, rwnd: %d}", pktsSent, 
				bytesSent, pktsRecv, bytesRecv, retrans, lost, rtt, rttvar, mss, snd_cwnd, snd_ssthresh,
				snd_una, snd_nxt, rwnd);
	}
}
