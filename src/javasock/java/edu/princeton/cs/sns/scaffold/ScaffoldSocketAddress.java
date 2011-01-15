package edu.princeton.cs.sns.scaffold;
import java.net.SocketAddress;

public class ScaffoldSocketAddress extends SocketAddress {
	ServiceId srvId;
	
	public ScaffoldSocketAddress(ServiceId srvId) {
		this.srvId = srvId;
	}

	public ServiceId getServiceId() {
		return srvId;
	}
}
