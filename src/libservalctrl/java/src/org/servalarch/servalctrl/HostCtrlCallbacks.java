package org.servalarch.servalctrl;

import java.net.InetAddress;

import org.servalarch.net.ServiceID;

public interface HostCtrlCallbacks {
	public void serviceRegistration(ServiceID id, int flags, int prefixBits,
			InetAddress addr, InetAddress oldAddr);
	public void serviceUnregistration(ServiceID id, int flags, int prefixBits,
			InetAddress addr);
	public void serviceGet(ServiceID id, int flags, int prefixBits,
			int priority, int weight, InetAddress addr);
}
