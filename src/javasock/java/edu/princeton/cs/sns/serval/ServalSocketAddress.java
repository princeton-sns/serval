package edu.princeton.cs.sns.serval;
import java.net.SocketAddress;

public class ServalSocketAddress extends SocketAddress {
	ServiceId srvId;
	
	public ServalSocketAddress(ServiceId srvId) {
		this.srvId = srvId;
	}

	public ServiceId getServiceId() {
		return srvId;
	}
}
