/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package serval.net;

public class ServiceId {
    private byte[] identifier = null;
    
    public ServiceId(byte[] id) {
        if (id.length != 20) {
            throw new IllegalArgumentException("Bad serviceID length");
        }
        this.identifier = id;
    }
    /**
       Convenience function that allows one to create a serviceID
       based on a short integer (2 bytes).
     */
    public ServiceId(short id) {
        this.identifier = new byte[20];
        this.identifier[0] = (byte)((id >> 8) & 0xff);
        this.identifier[1] = (byte)((id) & 0xff);
    }
    public byte[] getId() {
        return identifier;
    }
    public int getLength() {
        return identifier.length;
    }
}
