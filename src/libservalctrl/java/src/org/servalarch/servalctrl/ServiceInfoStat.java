/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.servalctrl;

import java.net.InetAddress;

import org.servalarch.net.ServiceID;

public class ServiceInfoStat extends ServiceInfo {
	long durationSec;
	long durationNsec;
	long packetsResolved;
	long bytesResolved;
	long bytesDropped;
	long tokensConsumed;

	public ServiceInfoStat(ServiceID id, short prefixBits, short flags,
			InetAddress addr, long ifindex, long priority, long weight,
			long idleTimeout, long hardTimeout, long durationSec,
			long durationNsec, long packetsResolved, long bytesResolved,
			long bytesDropped, long tokensConsumed) {
		super(id, prefixBits, flags, addr, ifindex, priority, weight,
				idleTimeout, hardTimeout);
		this.durationSec = durationSec;
		this.durationNsec = durationNsec;
		this.packetsResolved = packetsResolved;
		this.bytesResolved = bytesResolved;
		this.bytesDropped = bytesDropped;
		this.tokensConsumed = tokensConsumed;
	}

	public long getDurationSec() {
		return durationSec;
	}

	public long getDurationNsec() {
		return durationNsec;
	}

	public long getPacketsResolved() {
		return packetsResolved;
	}

	public long getBytesResolved() {
		return bytesResolved;
	}

	public long getBytesDropped() {
		return bytesDropped;
	}

	public long getTokensConsumed() {
		return tokensConsumed;
	}
}
