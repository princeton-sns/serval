/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.net;

public class ServiceID {
    private byte[] identifier = null;
    public static final int SERVICE_ID_MAX_BITS = 256;
    public static final int SERVICE_ID_MAX_LENGTH = 32;
    private String idStr = null;
    
    public ServiceID() {
        // Creates an invalid serviceID
    }
    public ServiceID(byte[] id) {
        if (id.length != SERVICE_ID_MAX_LENGTH) {
            throw new IllegalArgumentException("Bad serviceID length");
        }
        this.identifier = id;
    }
    /**
       Convenience function that allows one to create a serviceID
       based on a short integer (2 bytes).
     */
    public ServiceID(short id) {
        this.identifier = new byte[SERVICE_ID_MAX_LENGTH];
        this.identifier[0] = 0;
        this.identifier[1] = 0;
        this.identifier[2] = (byte)((id >> 8) & 0xff);
        this.identifier[3] = (byte)((id) & 0xff);
    }
    /*
       Convenience function that allows one to create a serviceID
       based on a integer (4 bytes).
     */
    public ServiceID(int id) {
        this.identifier = new byte[SERVICE_ID_MAX_LENGTH];
        this.identifier[0] = (byte)((id >> 24) & 0xff);
        this.identifier[1] = (byte)((id >> 16) & 0xff);
        this.identifier[2] = (byte)((id >> 8) & 0xff);
        this.identifier[3] = (byte)((id) & 0xff);
    }
    
    public byte[] getID() {
        return identifier;
    }

    public int getLength() {
        return identifier != null ? identifier.length : 0;
    }
    
    public boolean valid() {
        // FIXME: do something useful here.
        return identifier != null;
    }
    
    @Override
    public String toString() {
    	if (identifier == null) 
    		return "0";
    	
    	if (idStr == null) {
    		idStr = "";
    		for (int i = 0; i < identifier.length; i++) {
    			idStr += String.format("%02x", identifier[i]);
    		}
    	}
    	return idStr;
    }
}
