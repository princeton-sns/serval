package org.servalarch.servalctrl;

import java.net.InetAddress;
import org.servalarch.net.ServiceID;

public class ServiceInfo {
	ServiceID service;
	int prefixBits;
	int flags;
	InetAddress addr;
	long ifindex;
	long priority;
	long weight;
	long idleTimeout;
	long hardTimeout;
	
	public ServiceInfo(ServiceID id, int prefixBits, int flags, 
			InetAddress addr, long ifindex, long priority, long weight, 
			long idleTimeout, long hardTimeout) {
		this.service = id;
		this.prefixBits = prefixBits;
		this.flags = flags;
		this.addr = addr;
		this.ifindex = ifindex;
		this.priority = priority;
		this.weight = weight;
		this.idleTimeout = idleTimeout;
		this.hardTimeout = hardTimeout;
	}
	
	public ServiceInfo(ServiceID id, short prefixBits, 
			InetAddress addr, long priority, long weight) {
		this(id, prefixBits, 0, addr, 0, priority, weight, 0, 0);
	}
	
	public ServiceInfo(ServiceID id, InetAddress addr) {
		this(id, 0, 0, addr, 0, 0, 0, 0, 0);
	}
	
	public ServiceID getServiceID() {
		return service;
	}

	public int getPrefixBits() {
		return prefixBits;
	}

	public int getFlags() {
		return flags;
	}

	public InetAddress getAddress() {
		return addr;
	}

	public long getIfindex() {
		return ifindex;
	}

	public long getPriority() {
		return priority;
	}

	public long getWeight() {
		return weight;
	}

	public long getIdleTimeout() {
		return idleTimeout;
	}

	public long getHardTimeout() {
		return hardTimeout;
	}
}
