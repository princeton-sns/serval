/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.net;

import java.net.SocketAddress;
import java.net.InetAddress;

public class ServalSocketAddress extends SocketAddress {
	/**
	 * 
	 */
	private static final long serialVersionUID = 5342119614494820939L;
	ServiceID serviceID;
    InetAddress address;
	 
	public ServalSocketAddress(ServiceID serviceID) {
		this.serviceID = serviceID;
        this.address = null;
	}
    
    public ServalSocketAddress(ServiceID serviceID, InetAddress address) {
		this.serviceID = serviceID;
        this.address = address;
	}
    
	public ServiceID getServiceID() {
		return serviceID;
	}

    public InetAddress getAddress() {
        return address;
    }

    public void setAddress(InetAddress address) {
        this.address = address;
    }

    public String getHostName() {
        return "getHostName not implemented";
    }
}