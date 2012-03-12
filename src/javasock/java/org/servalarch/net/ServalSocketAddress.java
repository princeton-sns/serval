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
    int prefix_bits;
	 
	public ServalSocketAddress(ServiceID serviceID) {
		this.serviceID = serviceID;
        this.address = null;
        this.prefix_bits = 0;
	}
    
    public ServalSocketAddress(ServiceID serviceID, InetAddress address) {
		this.serviceID = serviceID;
        this.address = address;
        this.prefix_bits = 0;
	}

	public ServalSocketAddress(ServiceID serviceID, int prefix_bits) {
		this.serviceID = serviceID;
        this.address = null;
        setPrefixBits(prefix_bits);
    }

    public ServalSocketAddress(ServiceID serviceID, InetAddress address, 
                               int prefix_bits) {
		this.serviceID = serviceID;
        this.address = address;
        setPrefixBits(prefix_bits);
	}
    
	public ServiceID getServiceID() {
		return serviceID;
	}

    public InetAddress getAddress() {
        return address;
    }

    public void setPrefixBits(int prefix_bits) {
        if (prefix_bits / 8 > serviceID.getLength() || prefix_bits < 0)
            this.prefix_bits = 0;
        else
            this.prefix_bits = prefix_bits;
    }

    public int getPrefixBits() {
        return prefix_bits;
    }

    public void setAddress(InetAddress address) {
        this.address = address;
    }

    public String getHostName() {
        return "getHostName not implemented";
    }
}
