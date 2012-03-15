/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.net;

/**
 * This interface defines a factory for Serval datagram socket
 * implementations. It is used by the class {@code
 * ServalDatagramSocket} to create a new datagram socket
 * implementation.
 * 
 * @see ServalDatagramSocket
 */
public interface ServalDatagramSocketImplFactory {
    
    /**
     * Creates a new {@code ServalDatagramSocketImpl} instance.
     * 
     * @return the new datagram socket implementation.
     */
    ServalDatagramSocketImpl createServalDatagramSocketImpl();
}
