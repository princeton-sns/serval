/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.net;

import java.net.SocketAddress;
import java.io.IOException;
import java.io.FileDescriptor;

/*
  This code is based on the DatagramSocket implementation from the
  Harmony project.
 */

/**
 * This class implements a Server Serval datagram socket for accepting
 * incoming connections
 *
 * @see DatagramPacket
 * @see ServalDatagramSocketImplFactory
 */
public class ServalServerDatagramSocket {

    ServalDatagramSocketImpl impl;
    private final ServalSocketAddress localAddress;
	
	private static final int LISTEN_BACKLOG = 10;

    /**
     * Creates a new server socket listening at specified name.
     * On the Android platform, the name is created in the Linux
     * abstract namespace (instead of on the filesystem).
     * 
     * @param serviceID to listen on
     * @throws IOException
     */
    public ServalServerDatagramSocket(ServiceID serviceID) 
        throws IOException {
        impl = new ServalDatagramSocketImpl();
        impl.create();
        localAddress = new ServalSocketAddress(serviceID);
        impl.bind(serviceID);
        impl.listen(LISTEN_BACKLOG);
    }

    /**
     * Creates a new server socket listening at specified name.
     * On the Android platform, the name is created in the Linux
     * abstract namespace (instead of on the filesystem).
     * 
     * @param serviceID to listen on
     * @param bindBits the number of bits of the serviceID to bind on
     * @throws IOException
     */
    public ServalServerDatagramSocket(ServiceID serviceID, int bindBits) 
        throws IOException {
        impl = new ServalDatagramSocketImpl();
        impl.create();
        localAddress = new ServalSocketAddress(serviceID, bindBits);
        impl.bind(serviceID, localAddress.getPrefixBits());
        impl.listen(LISTEN_BACKLOG);
    }

    /**
     * Create a ServalServerDatagramSocket from a file descriptor
     * that's already been created and bound. listen() will be called
     * immediately on it.  Used for cases where file descriptors are
     * passed in via environment variables
     *
     * @param fd bound file descriptor
     * @throws IOException
     */
    public ServalServerDatagramSocket(FileDescriptor fd) throws IOException {
        impl = new ServalDatagramSocketImpl(fd);
        localAddress = impl.getLocalSocketAddress();
        impl.listen(LISTEN_BACKLOG);
    }

    /**
     * Obtains the socket's local address
     *
     * @return Serval socket address
     */
    public SocketAddress geLocalSocketAddress()
    {
        return localAddress;
    }

    /**
     * Accepts a new connection to the socket. Blocks until a new
     * connection arrives.
     *
     * @return a socket representing the new connection.
     * @throws IOException
     */
    public ServalDatagramSocket accept() throws IOException
    {
        ServalDatagramSocketImpl acceptedImpl = new ServalDatagramSocketImpl();

        impl.accept(acceptedImpl);

        return new ServalDatagramSocket(acceptedImpl);
    }

    /**
     * Returns file descriptor or null if not yet open/already closed
     *
     * @return fd or null
     */
    public FileDescriptor getFileDescriptor() {
        return impl.getFileDescriptor();
    }

    /**
     * Closes server socket.
     * 
     * @throws IOException
     */
    public void close() throws IOException
    {
        impl.close();
    }
}
