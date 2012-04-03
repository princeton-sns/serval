package org.servalarch.serval;

import java.io.Serializable;

public class ServiceRule implements Serializable {

	private static final long serialVersionUID = -3598472596390768534L;

	public final String srvID;
	public final String IP;
	
	public ServiceRule(String srvID, String IP) {
		this.srvID = srvID;
		this.IP = IP;
	}
}
