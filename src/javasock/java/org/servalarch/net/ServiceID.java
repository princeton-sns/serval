/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.net;

/**
 * ServiceIDs are essentially reversed domain names. ServiceIDs can
 * also contain wildcards, but these are only allowed at the beginning
 * of a domain name and must be followed by a dot.
 */
public class ServiceID {
    private String identifier;
    public static final int SERVICE_ID_MAX_LENGTH = 105;
    private native String fqdnToService(String id);
    private native String serviceToFqdn(String service);
    
    public ServiceID(String id) {
        if (id.length() > SERVICE_ID_MAX_LENGTH) {
            throw new IllegalArgumentException("Invalid domain name length");
        }
        this.identifier = fqdnToService(id);

        if (this.identifier == null) {
            throw new IllegalArgumentException("Invalid domain name");
        }
    } 

    public ServiceID(byte[] id) {
        this(new String(id));
    } 

    public ServiceID(char[] id) {
        this(new String(id));
    } 
   
    public String getID() {
        return identifier;
    }
    
    public String getDomainName() {
        return serviceToFqdn(identifier);
    }

    public int getLength() {
        return identifier.length();
    }
    
    @Override
    public String toString() {
    	return identifier;
    }

	static {
		System.loadLibrary("servalnet_jni");
	}
}
