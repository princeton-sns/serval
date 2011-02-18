/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package serval.net;

import java.net.SocketAddress;
import java.net.SocketException;
import java.io.IOException;
import java.nio.channels.DatagramChannel;
import serval.netPlainDatagramSocketImpl;

/*
  This code is based on the DatagramSocket implementation from the
  Harmony project.
 */

/**
 * This class implements a Serval datagram socket for sending and
 * receiving {@code DatagramPacket}. A {@code ServalDatagramSocket}
 * object can be used for both endpoints of a connection for a packet
 * delivery service.
 *
 * @see DatagramPacket
 * @see ServalDatagramSocketImplFactory
 */
public class ServalDatagramSocket {

    ServalDatagramSocketImpl impl;
    private final ServalSocketAddress localAddress;
	
	private static final int LISTEN_BACKLOG = 10;

    /**
     * Crewates a new server socket listening at specified name.
     * On the Android platform, the name is created in the Linux
     * abstract namespace (instead of on the filesystem).
     * 
     * @param name address for socket
     * @throws IOException
     */
    public ServalServerDatagramSocket(ServiceID serviceID) 
        throws IOException {
        impl = new ServalDatagramSocketImpl();

        impl.create(true);

        localAddress = new ServalSocketAddress(serviceID);
        impl.bind(serviceID);
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
        impl.listen(LISTEN_BACKLOG);
        localAddress = impl.getSockAddress();
    }

    /**
     * Obtains the socket's local address
     *
     * @return local address
     */
    public LocalSocketAddress getLocalSocketAddress()
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
    public LocalSocket accept() throws IOException
    {
        LocalSocketImpl acceptedImpl = new LocalSocketImpl();

        impl.accept (acceptedImpl);

        return new LocalSocket(acceptedImpl);
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
