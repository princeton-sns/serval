/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package serval.net;

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
