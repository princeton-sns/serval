/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.servalarch.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.BindException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketOptions;
import java.net.UnknownHostException;
import java.nio.channels.SocketChannel;
import org.servalarch.platform.ServalNetworkStack;

/**
 * Provides a client-side TCP socket.
 */
public class ServalSocket {

    ServalSocketImpl impl;

    static ServalSocketImplFactory factory;

    private volatile boolean isCreated = false;

    private boolean isBound = false;

    private boolean isConnected = false;

    private boolean isClosed = false;

    private boolean isInputShutdown = false;

    private boolean isOutputShutdown = false;

    private static class ConnectLock {
    }

    private Object connectLock = new ConnectLock();

    static final int MULTICAST_IF = 1;

    static final int MULTICAST_TTL = 2;

    static final int TCP_NODELAY = 4;

    static final int FLAG_SHUTDOWN = 8;
    /*
    static private Logger logger;

    static private Logger getLogger() {
        if (logger == null) {
            logger = Logger.getLogger(ServalSocket.class.getName());
        }
        return logger;
    }
*/
    // BEGIN android-removed: we do this statically, when we start the VM.
    // static {
    //     Platform.getNetworkSystem().oneTimeInitialization(true);
    // }
    // END android-removed

    /**
     * Creates a new unconnected socket. When a SocketImplFactory is defined it
     * creates the internal socket implementation, otherwise the default socket
     * implementation will be used for this socket.
     *
     * @see SocketImplFactory
     * @see SocketImpl
     */
    public ServalSocket() {
        impl = factory != null ? factory.createSocketImpl()
                : new ServalPlainSocketImpl();
    }

    // BEGIN android-added
    /**
     * Tries to connect a socket to all IP addresses of the given hostname.
     *
     * @param dstService
     *            the target service identifier to connect to.
     * @param dstName
     *            the target host name or IP address to connect to.
     * @param localService
     * 			  the local service identifier to bind to.
     * @param localAddress
     *            the address on the local host to bind to.
     * @param streaming
     *            if {@code true} a streaming socket is returned, a datagram
     *            socket otherwise.
     * @throws UnknownHostException
     *             if the host name could not be resolved into an IP address.
     * @throws IOException
     *             if an error occurs while creating the socket.
     * @throws SecurityException
     *             if a security manager exists and it denies the permission to
     *             connect to the given address and port.
     */
    /*
    private void tryAllAddresses(ServiceID dstServiceID, String dstName, 
    		ServiceID localServiceID, InetAddress localAddress, 
    		boolean streaming) throws IOException {
        InetAddress[] dstAddresses = InetAddress.getAllByName(dstName);
        // Loop through all the destination addresses except the last, trying to
        // connect to each one and ignoring errors. There must be at least one
        // address, or getAllByName would have thrown UnknownHostException.
        InetAddress dstAddress;
        for (int i = 0; i < dstAddresses.length - 1; i++) {
            dstAddress = dstAddresses[i];
            try {
                checkDestination(dstServiceID, dstAddress);
                startupSocket(dstServiceID, dstAddress, localServiceID, localAddress, streaming);
                return;
            } catch(SecurityException e1) {
           
            } catch(IOException e2) {
                
            }
        }

        // Now try to connect to the last address in the array, handing back to
        // the caller any exceptions that are thrown.
        dstAddress = dstAddresses[dstAddresses.length - 1];
        checkDestination(dstServiceID, dstAddress);
        startupSocket(dstServiceID, dstAddress, localServiceID, localAddress, streaming);
    }
    */
    // END android-added

    /**
     * Creates a new streaming socket connected to the target host specified by
     * the parameters {@code dstName} and {@code dstPort}. The socket is bound
     * to any available port on the local host.
     * <p><strong>Implementation note:</strong> this implementation tries each
     * IP address for the given hostname until it either connects successfully
     * or it exhausts the set. It will try both IPv4 and IPv6 addresses in the
     * order specified by the system property {@code "java.net.preferIPv6Addresses"}.
     *
     * @param dstName
     *            the target host name or IP address to connect to.
     * @param dstPort
     *            the port on the target host to connect to.
     * @throws UnknownHostException
     *             if the host name could not be resolved into an IP address.
     * @throws IOException
     *             if an error occurs while creating the socket.
     * @throws SecurityException
     *             if a security manager exists and it denies the permission to
     *             connect to the given address and port.
     */
    /*
    public ServalSocket(String serviceName) 
    		throws UnknownHostException, IOException {
        this(dstName, dstPort, null, 0);
    }
 	*/
    /**
     * Creates a new streaming socket connected to the target host specified by
     * the parameters {@code dstName} and {@code dstPort}. On the local endpoint
     * the socket is bound to the given address {@code localAddress} on port
     * {@code localPort}.
     *
     * If {@code host} is {@code null} a loopback address is used to connect to.
     * <p><strong>Implementation note:</strong> this implementation tries each
     * IP address for the given hostname until it either connects successfully
     * or it exhausts the set. It will try both IPv4 and IPv6 addresses in the
     * order specified by the system property {@code "java.net.preferIPv6Addresses"}.
     *
     * @param dstName
     *            the target host name or IP address to connect to.
     * @param dstPort
     *            the port on the target host to connect to.
     * @param localAddress
     *            the address on the local host to bind to.
     * @param localPort
     *            the port on the local host to bind to.
     * @throws UnknownHostException
     *             if the host name could not be resolved into an IP address.
     * @throws IOException
     *             if an error occurs while creating the socket.
     * @throws SecurityException
     *             if a security manager exists and it denies the permission to
     *             connect to the given address and port.
     */
    /*
    public ServalSocket(String dstName, int dstPort, InetAddress localAddress,
            int localPort) throws IOException {
        this();
        // BEGIN android-changed
        tryAllAddresses(dstName, dstPort, localAddress, localPort, true);
        // END android-changed
    }
	*/

	/**
	 * Creates a new streaming socket connected to the target service and
	 * instance specified by the parameter {@code dstServiceID}. The socket is
	 * bound to any available port on the local host.
	 * 
	 * @param dstServiceID
	 *            the service identifier to connect to.
	 * @throws IOException
	 *             if an error occurs while creating the socket.
	 * @throws SecurityException
	 *             if a security manager exists and it denies the permission to
	 *             connect to the given address and port.
	 */
	public ServalSocket(ServiceID dstServiceID, ServiceID localServiceID) 
			throws IOException {
		this();
		checkDestination(dstServiceID, null);
		startupSocket(dstServiceID, null, localServiceID, null, true);
	}
	
	/**
	 * Creates a new streaming socket connected to the target service and
	 * instance specified by the parameter {@code dstServiceID}. The socket is
	 * bound to any available port on the local host.
	 * 
	 * @param dstServiceID
	 *            the service identifier to connect to.
	 * @throws IOException
	 *             if an error occurs while creating the socket.
	 * @throws SecurityException
	 *             if a security manager exists and it denies the permission to
	 *             connect to the given address and port.
	 */
	public ServalSocket(ServiceID dstServiceID) throws IOException {
		this();
		checkDestination(dstServiceID, null);
		startupSocket(dstServiceID, null, null, null, true);
	}

	/**
	 * Creates a new streaming socket connected to the target service and
	 * instance specified by the parameters {@code dstServiceID} and
	 * {@code dstAddress}. The socket is bound to any available port on the
	 * local host.
	 * 
	 * @param dstServiceID
	 *            the service identifier to connect to.
	 * @param dstAddress
	 *            the target host address to connect to.
	 * @throws IOException
	 *             if an error occurs while creating the socket.
	 * @throws SecurityException
	 *             if a security manager exists and it denies the permission to
	 *             connect to the given address and port.
	 */
	public ServalSocket(ServiceID dstServiceID, InetAddress dstAddress)
			throws IOException {
		this();
		checkDestination(dstServiceID, dstAddress);
		startupSocket(dstServiceID, dstAddress, null, null, true);
	}

	/**
	 * Creates a new streaming socket connected to the target service and host
	 * specified by the parameters {@code dstService} and {@code dstAddress}. On
	 * the local endpoint the socket is bound to the given service
	 * {@code localServiceID} on address {@code localAddress}.
	 * 
	 * @param dstServiceID
	 *            the target serviceID to connect to.
	 * @param dstAddress
	 *            the target host address to connect to.
	 * @param localServiceID
	 *            the local serviceID to bind to.
	 * @param localAddress
	 *            the address on the local host to bind to.
	 * @throws IOException
	 *             if an error occurs while creating the socket.
	 * @throws SecurityException
	 *             if a security manager exists and it denies the permission to
	 *             connect to the given address and port.
	 */
	public ServalSocket(ServiceID dstServiceID, InetAddress dstAddress,
			ServiceID localServiceID, InetAddress localAddress)
			throws IOException {
		this();
		checkDestination(dstServiceID, dstAddress);
		startupSocket(dstServiceID, dstAddress, localServiceID, localAddress,
				true);
	}

    /**
     * Creates an unconnected socket with the given socket implementation.
     *
     * @param anImpl
     *            the socket implementation to be used.
     * @throws SocketException
     *             if an error occurs while creating the socket.
     */
    protected ServalSocket(ServalSocketImpl anImpl) throws SocketException {
        impl = anImpl;
    }

    /**
     * Checks whether the connection destination satisfies the security policy
     * and the validity of the port range.
     *
     * @param destAddr
     *            the destination host address.
     * @param dstPort
     *            the port on the destination host.
     */
    void checkDestination(ServiceID serviceID, InetAddress destAddr) {
        if (destAddr != null)
            checkConnectPermission(destAddr.getHostAddress());
    }

    /**
     * Checks whether the connection destination satisfies the security policy.
     *
     * @param hostname
     *            the destination hostname.
     * @param dstPort
     *            the port on the destination host.
     */
    private void checkConnectPermission(String hostname) {
    	/*
        SecurityManager security = System.getSecurityManager();
        if (security != null) {
            security.checkConnect(hostname);
        }
        */
    }

    /**
     * Closes the socket. It is not possible to reconnect or rebind to this
     * socket thereafter which means a new socket instance has to be created.
     *
     * @throws IOException
     *             if an error occurs while closing the socket.
     */
    public synchronized void close() throws IOException {
        isClosed = true;
        impl.close();
    }

    /**
     * Gets the IP address of the target host this socket is connected to.
     *
     * @return the IP address of the connected target host or {@code null} if
     *         this socket is not yet connected.
     */
    public InetAddress getInetAddress() {
        if (!isConnected()) {
            return null;
        }
        return impl.getInetAddress();
    }

    /**
     * Gets an input stream to read data from this socket.
     *
     * @return the byte-oriented input stream.
     * @throws IOException
     *             if an error occurs while creating the input stream or the
     *             socket is in an invalid state.
     */
    public InputStream getInputStream() throws IOException {
        checkClosedAndCreate(false);
        if (isInputShutdown()) {
            throw new SocketException("Socket is shut down!");
        }
        return impl.getInputStream();
    }

    /**
     * Gets the setting of the socket option {@code SocketOptions.SO_KEEPALIVE}.
     *
     * @return {@code true} if the {@code SocketOptions.SO_KEEPALIVE} is
     *         enabled, {@code false} otherwise.
     * @throws SocketException
     *             if an error occurs while reading the socket option.
     * @see SocketOptions#SO_KEEPALIVE
     */
    public boolean getKeepAlive() throws SocketException {
        checkClosedAndCreate(true);
        return ((Boolean) impl.getOption(SocketOptions.SO_KEEPALIVE))
                .booleanValue();
    }

    /**
     * Gets the local IP address this socket is bound to.
     *
     * @return the local IP address of this socket or {@code InetAddress.ANY} if
     *         the socket is unbound.
     */
    public InetAddress getLocalAddress() {
        if (!isBound()) {
            try {
				return Inet4Address.getByAddress(new byte[] { 0, 0, 0, 0 });
			} catch (UnknownHostException e) {
				return null;
			}
        }
        return ServalNetworkStack.getInstance().getSocketLocalAddress(impl.fd);
    }

    /**
     * Gets the local serviceID this socket is bound to.
     *
     * @return the serviceID of this socket or {@code null} if the socket is
     *         unbound.
     */
    public ServiceID getLocalServiceID() {
        if (!isBound()) {
            return null;
        }
        return impl.getLocalServiceID();
    }

    /**
     * Gets an output stream to write data into this socket.
     *
     * @return the byte-oriented output stream.
     * @throws IOException
     *             if an error occurs while creating the output stream or the
     *             socket is in an invalid state.
     */
    public OutputStream getOutputStream() throws IOException {
        checkClosedAndCreate(false);
        if (isOutputShutdown()) {
            throw new SocketException("Output is shut down!");
        }
        return impl.getOutputStream();
    }

    /**
     * Gets the serviceID of the target service this socket is connected to.
     *
     * @return the serviceID of the connected target service or {@code null} if this
     *         socket is not yet connected.
     */
    public ServiceID getServiceID() {
        if (!isConnected()) {
            return null;
        }
        return impl.getServiceID();
    }

    /**
     * Gets the value of the socket option {@code SocketOptions.SO_LINGER}.
     *
     * @return the current value of the option {@code SocketOptions.SO_LINGER}
     *         or {@code -1} if this option is disabled.
     * @throws SocketException
     *             if an error occurs while reading the socket option.
     * @see SocketOptions#SO_LINGER
     */
    public int getSoLinger() throws SocketException {
        checkClosedAndCreate(true);
        return ((Integer) impl.getOption(SocketOptions.SO_LINGER)).intValue();
    }

    /**
     * Gets the receive buffer size of this socket.
     *
     * @return the current value of the option {@code SocketOptions.SO_RCVBUF}.
     * @throws SocketException
     *             if an error occurs while reading the socket option.
     * @see SocketOptions#SO_RCVBUF
     */
    public synchronized int getReceiveBufferSize() throws SocketException {
        checkClosedAndCreate(true);
        return ((Integer) impl.getOption(SocketOptions.SO_RCVBUF)).intValue();
    }

    /**
     * Gets the send buffer size of this socket.
     *
     * @return the current value of the option {@code SocketOptions.SO_SNDBUF}.
     * @throws SocketException
     *             if an error occurs while reading the socket option.
     * @see SocketOptions#SO_SNDBUF
     */
    public synchronized int getSendBufferSize() throws SocketException {
        checkClosedAndCreate(true);
        return ((Integer) impl.getOption(SocketOptions.SO_SNDBUF)).intValue();
    }

    /**
     * Gets the timeout for this socket during which a reading operation shall
     * block while waiting for data.
     *
     * @return the current value of the option {@code SocketOptions.SO_TIMEOUT}
     *         or {@code 0} which represents an infinite timeout.
     * @throws SocketException
     *             if an error occurs while reading the socket option.
     * @see SocketOptions#SO_TIMEOUT
     */
    public synchronized int getSoTimeout() throws SocketException {
        checkClosedAndCreate(true);
        return ((Integer) impl.getOption(SocketOptions.SO_TIMEOUT)).intValue();
    }

    /**
     * Gets the setting of the socket option {@code SocketOptions.TCP_NODELAY}.
     *
     * @return {@code true} if the {@code SocketOptions.TCP_NODELAY} is enabled,
     *         {@code false} otherwise.
     * @throws SocketException
     *             if an error occurs while reading the socket option.
     * @see SocketOptions#TCP_NODELAY
     */
    public boolean getTcpNoDelay() throws SocketException {
        checkClosedAndCreate(true);
        return ((Boolean) impl.getOption(SocketOptions.TCP_NODELAY))
                .booleanValue();
    }

    /**
     * Sets the state of the {@code SocketOptions.SO_KEEPALIVE} for this socket.
     *
     * @param value
     *            the state whether this option is enabled or not.
     * @throws SocketException
     *             if an error occurs while setting the option.
     * @see SocketOptions#SO_KEEPALIVE
     */
    public void setKeepAlive(boolean value) throws SocketException {
        if (impl != null) {
            checkClosedAndCreate(true);
            impl.setOption(SocketOptions.SO_KEEPALIVE, value ? Boolean.TRUE
                    : Boolean.FALSE);
        }
    }

    /**
     * Sets the internal factory for creating socket implementations. This may
     * only be executed once during the lifetime of the application.
     *
     * @param fac
     *            the socket implementation factory to be set.
     * @throws IOException
     *             if the factory has been already set.
     */
    public static synchronized void setSocketImplFactory(ServalSocketImplFactory fac)
            throws IOException {
        SecurityManager security = System.getSecurityManager();
        if (security != null) {
            security.checkSetFactory();
        }
        if (factory != null) {
            throw new SocketException("no factory");
        }
        factory = fac;
    }

    /**
     * Sets the send buffer size of this socket.
     *
     * @param size
     *            the buffer size in bytes. This value must be a positive number
     *            greater than {@code 0}.
     * @throws SocketException
     *             if an error occurs while setting the size or the given value
     *             is an invalid size.
     * @see SocketOptions#SO_SNDBUF
     */
    public synchronized void setSendBufferSize(int size) throws SocketException {
        checkClosedAndCreate(true);
        if (size < 1) {
            throw new IllegalArgumentException("bad size");
        }
        impl.setOption(SocketOptions.SO_SNDBUF, Integer.valueOf(size));
    }

    /**
     * Sets the receive buffer size of this socket.
     *
     * @param size
     *            the buffer size in bytes. This value must be a positive number
     *            greater than {@code 0}.
     * @throws SocketException
     *             if an error occurs while setting the size or the given value
     *             is an invalid size.
     * @see SocketOptions#SO_RCVBUF
     */
    public synchronized void setReceiveBufferSize(int size)
            throws SocketException {
        checkClosedAndCreate(true);
        if (size < 1) {
            throw new IllegalArgumentException("bad size");
        }
        impl.setOption(SocketOptions.SO_RCVBUF, Integer.valueOf(size));
    }

    /**
     * Sets the state of the {@code SocketOptions.SO_LINGER} with the given
     * timeout in seconds. The timeout value for this option is silently limited
     * to the maximum of {@code 65535}.
     *
     * @param on
     *            the state whether this option is enabled or not.
     * @param timeout
     *            the linger timeout value in seconds.
     * @throws SocketException
     *             if an error occurs while setting the option.
     * @see SocketOptions#SO_LINGER
     */
    public void setSoLinger(boolean on, int timeout) throws SocketException {
        checkClosedAndCreate(true);
        if (on && timeout < 0) {
            throw new IllegalArgumentException("bad value");
        }
        // BEGIN android-changed
        /*
         * The spec indicates that the right way to turn off an option
         * is to pass Boolean.FALSE, so that's what we do here.
         */
        if (on) {
            if (timeout > 65535) {
                timeout = 65535;
            }
            impl.setOption(SocketOptions.SO_LINGER, Integer.valueOf(timeout));
        } else {
            impl.setOption(SocketOptions.SO_LINGER, Boolean.FALSE);
        }
        // END android-changed
    }

    /**
     * Sets the reading timeout in milliseconds for this socket. The read
     * operation will block indefinitely if this option value is set to {@code
     * 0}. The timeout must be set before calling the read operation. A
     * {@code SocketTimeoutException} is thrown when this timeout expires.
     *
     * @param timeout
     *            the reading timeout value as number greater than {@code 0} or
     *            {@code 0} for an infinite timeout.
     * @throws SocketException
     *             if an error occurs while setting the option.
     * @see SocketOptions#SO_TIMEOUT
     */
    public synchronized void setSoTimeout(int timeout) throws SocketException {
        checkClosedAndCreate(true);
        if (timeout < 0) {
            throw new IllegalArgumentException("negative timeout");
        }
        impl.setOption(SocketOptions.SO_TIMEOUT, Integer.valueOf(timeout));
    }

    /**
     * Sets the state of the {@code SocketOptions.TCP_NODELAY} for this socket.
     *
     * @param on
     *            the state whether this option is enabled or not.
     * @throws SocketException
     *             if an error occurs while setting the option.
     * @see SocketOptions#TCP_NODELAY
     */
    public void setTcpNoDelay(boolean on) throws SocketException {
        checkClosedAndCreate(true);
        impl.setOption(SocketOptions.TCP_NODELAY, Boolean.valueOf(on));
    }

    /**
     * Creates a stream socket, binds it to the nominated local address/port,
     * then connects it to the nominated destination address/port.
     *
     * @param dstService
     * 			  the destination service identifier.
     * @param dstAddress
     *            the destination host address.
     * @param localService
     * 			  the local service identifier.
     * @param localAddress
     *            the address on the local machine to bind.
     * @throws IOException
     *             thrown if an error occurs during the bind or connect
     *             operations.
     */
    void startupSocket(ServiceID dstService, InetAddress dstAddress, 
                       ServiceID localService, InetAddress localAddress, 
                       boolean streaming)
            throws IOException {
        		
        if (dstService == null)
            throw new IOException("Bad serviceID");

        synchronized (this) {
            impl.create(streaming);
            isCreated = true;
            try {
                if (!streaming) {
                    impl.bind(localService, localAddress);
                }
                isBound = true;
                impl.connect(dstService, dstAddress);
                isConnected = true;
            } catch (IOException e) {
                impl.close();
                throw e;
            }
        }
    }

    /**
     * Returns a {@code String} containing a concise, human-readable description of the
     * socket.
     *
     * @return the textual representation of this socket.
     */
    @Override
    public String toString() {
        if (!isConnected()) {
            return "Socket[unconnected]";
        }
        return impl.toString();
    }

    /**
     * Closes the input stream of this socket. Any further data sent to this
     * socket will be discarded. Reading from this socket after this method has
     * been called will return the value {@code EOF}.
     *
     * @throws IOException
     *             if an error occurs while closing the socket input stream.
     * @throws SocketException
     *             if the input stream is already closed.
     */
    public void shutdownInput() throws IOException {
        if (isInputShutdown()) {
            throw new SocketException("Input is shut down"); //$NON-NLS-1$
        }
        checkClosedAndCreate(false);
        impl.shutdownInput();
        isInputShutdown = true;
    }

    /**
     * Closes the output stream of this socket. All buffered data will be sent
     * followed by the termination sequence. Writing to the closed output stream
     * will cause an {@code IOException}.
     *
     * @throws IOException
     *             if an error occurs while closing the socket output stream.
     * @throws SocketException
     *             if the output stream is already closed.
     */
    public void shutdownOutput() throws IOException {
        if (isOutputShutdown()) {
            throw new SocketException("Output is shut down");
        }
        checkClosedAndCreate(false);
        impl.shutdownOutput();
        isOutputShutdown = true;
    }

    /**
     * Checks whether the socket is closed, and throws an exception. Otherwise
     * creates the underlying SocketImpl.
     *
     * @throws SocketException
     *             if the socket is closed.
     */
    private void checkClosedAndCreate(boolean create) throws SocketException {
        if (isClosed()) {
            throw new SocketException("Socket is closed");
        }
        if (!create) {
            if (!isConnected()) {
                throw new SocketException("Socket is not connected");
                // a connected socket must be created
            }

            /*
             * return directly to fix a possible bug, if !create, should return
             * here
             */
            return;
        }
        if (isCreated) {
            return;
        }
        synchronized (this) {
            if (isCreated) {
                return;
            }
            try {
                impl.create(true);
            } catch (SocketException e) {
                throw e;
            } catch (IOException e) {
                throw new SocketException(e.toString());
            }
            isCreated = true;
        }
    }

    /**
     * Gets the local address and port of this socket as a SocketAddress or
     * {@code null} if the socket is unbound. This is useful on multihomed
     * hosts.
     *
     * @return the bound local socket address and port.
     */
    public SocketAddress getLocalSocketAddress() {
        if (!isBound()) {
            return null;
        }
        return new ServalSocketAddress(getLocalServiceID(), getLocalAddress());
    }

    /**
     * Gets the remote address and port of this socket as a {@code
     * SocketAddress} or {@code null} if the socket is not connected.
     *
     * @return the remote socket address and port.
     */
    public SocketAddress getRemoteSocketAddress() {
        if (!isConnected()) {
            return null;
        }
        return new ServalSocketAddress(getServiceID(), getInetAddress());
    }

    /**
     * Returns whether this socket is bound to a local address and port.
     *
     * @return {@code true} if the socket is bound to a local address, {@code
     *         false} otherwise.
     */
    public boolean isBound() {
        return isBound;
    }

    /**
     * Returns whether this socket is connected to a remote host.
     *
     * @return {@code true} if the socket is connected, {@code false} otherwise.
     */
    public boolean isConnected() {
        return isConnected;
    }

    /**
     * Returns whether this socket is closed.
     *
     * @return {@code true} if the socket is closed, {@code false} otherwise.
     */
    public boolean isClosed() {
        return isClosed;
    }

    /**
     * Binds this socket to the given local host address and port specified by
     * the SocketAddress {@code localAddr}. If {@code localAddr} is set to
     * {@code null}, this socket will be bound to an available local address on
     * any free port.
     *
     * @param localAddr
     *            the specific address and port on the local machine to bind to.
     * @throws IllegalArgumentException
     *             if the given SocketAddress is invalid or not supported.
     * @throws IOException
     *             if the socket is already bound or an error occurs while
     *             binding.
     */
    public void bind(SocketAddress localAddr) throws IOException {
        checkClosedAndCreate(true);
        if (isBound()) {
            throw new BindException("Socket already bound");
        }

        InetAddress addr = Inet4Address.getByAddress(new byte[] { 0, 0, 0, 0 });
        ServiceID localServiceID = null;
        
        if (localAddr != null) {
            if (!(localAddr instanceof ServalSocketAddress)) {
                throw new IllegalArgumentException("Bad address type: " + localAddr.getClass());
            }
            ServalSocketAddress servalAddr = (ServalSocketAddress) localAddr;
            if ((localServiceID = servalAddr.getServiceID()) == null) {
                throw new SocketException("Bad address: " + servalAddr.getHostName());
            }
            addr = servalAddr.getAddress();
        }

        if (localServiceID == null)
        	throw new SocketException("Bad address - No serviceID");
        
        synchronized (this) {
            try {
                impl.bind(localServiceID, addr);
                isBound = true;
            } catch (IOException e) {
                impl.close();
                throw e;
            }
        }
    }
    
    /**
     * Connects this socket to the given remote host address and port specified
     * by the SocketAddress {@code remoteAddr}.
     *
     * @param serviceID
     *            the address and port of the remote host to connect to.
     * @throws IllegalArgumentException
     *             if the given SocketAddress is invalid or not supported.
     * @throws IOException
     *             if the socket is already connected or an error occurs while
     *             connecting.
     */
    public void connect(ServiceID serviceID) throws IOException {
        connect(new ServalSocketAddress(serviceID), 0);
    }
    
    /**
     * Connects this socket to the given remote host address and port specified
     * by the SocketAddress {@code remoteAddr}.
     *
     * @param serviceID
     *            the address and port of the remote host to connect to.
     * @param timeout
     * 			  the timeout for connecting.
     * @throws IllegalArgumentException
     *             if the given SocketAddress is invalid or not supported.
     * @throws IOException
     *             if the socket is already connected or an error occurs while
     *             connecting.
     */
    public void connect(ServiceID serviceID, int timeout) throws IOException {
        connect(new ServalSocketAddress(serviceID), timeout);
    }
    
    /**
     * Connects this socket to the given remote serviceID and host address specified
     * by the SocketAddress {@code remoteAddr}.
     *
     * @param remoteAddr
     *            the serviceID and address of the remote service to connect to.
     * @throws IllegalArgumentException
     *             if the given SocketAddress is invalid or not supported.
     * @throws IOException
     *             if the socket is already connected or an error occurs while
     *             connecting.
     */
    public void connect(SocketAddress remoteAddr) throws IOException {
        connect(remoteAddr, 0);
    }

    /**
     * Connects this socket to the given remote serviceID and host address specified
     * by the SocketAddress {@code remoteAddr} with the specified timeout. The
     * connecting method will block until the connection is established or an
     * error occurred.
     *
     * @param remoteAddr
     *            the serviceID and address of the remote service to connect to.
     * @param timeout
     *            the timeout value in milliseconds or {@code 0} for an infinite
     *            timeout.
     * @throws IllegalArgumentException
     *             if the given SocketAddress is invalid or not supported or the
     *             timeout value is negative.
     * @throws IOException
     *             if the socket is already connected or an error occurs while
     *             connecting.
     */
    public void connect(SocketAddress remoteAddr, int timeout)
            throws IOException {
        checkClosedAndCreate(true);
        if (timeout < 0) {
            throw new IllegalArgumentException("Negative timeout"); 
        }
        if (isConnected()) {
            throw new SocketException("Already connected");
        }
        if (remoteAddr == null) {
            throw new IllegalArgumentException("Bad remote socket address");
        }

        if (!(remoteAddr instanceof ServalSocketAddress)) {
            throw new IllegalArgumentException("Bad socket address class: " + 
            		remoteAddr.getClass()); 
        }
        ServalSocketAddress servalAddr = (ServalSocketAddress) remoteAddr;
        ServiceID serviceID = null;
        
        if ((serviceID = servalAddr.getServiceID()) == null) {
            throw new UnknownHostException("No remote serviceID");
        }
        InetAddress addr = servalAddr.getAddress();

        checkDestination(serviceID, addr);
        
        synchronized (connectLock) {
            try {
                if (!isBound()) {
                    // socket already created at this point by earlier call or
                    // checkClosedAndCreate this caused us to lose socket
                    // options on create
                    // impl.create(true);
                    isBound = true;
                }
                impl.connect(remoteAddr, timeout);
                isConnected = true;
            } catch (IOException e) {
                impl.close();
                throw e;
            }
        }
    }

    /**
     * Returns whether the incoming channel of the socket has already been
     * closed.
     *
     * @return {@code true} if reading from this socket is not possible anymore,
     *         {@code false} otherwise.
     */
    public boolean isInputShutdown() {
        return isInputShutdown;
    }

    /**
     * Returns whether the outgoing channel of the socket has already been
     * closed.
     *
     * @return {@code true} if writing to this socket is not possible anymore,
     *         {@code false} otherwise.
     */
    public boolean isOutputShutdown() {
        return isOutputShutdown;
    }

    /**
     * Sets the state of the {@code SocketOptions.SO_REUSEADDR} for this socket.
     *
     * @param reuse
     *            the state whether this option is enabled or not.
     * @throws SocketException
     *             if an error occurs while setting the option.
     * @see SocketOptions#SO_REUSEADDR
     */
    public void setReuseAddress(boolean reuse) throws SocketException {
        checkClosedAndCreate(true);
        impl.setOption(SocketOptions.SO_REUSEADDR, reuse ? Boolean.TRUE
                : Boolean.FALSE);
    }

    /**
     * Gets the setting of the socket option {@code SocketOptions.SO_REUSEADDR}.
     *
     * @return {@code true} if the {@code SocketOptions.SO_REUSEADDR} is
     *         enabled, {@code false} otherwise.
     * @throws SocketException
     *             if an error occurs while reading the socket option.
     * @see SocketOptions#SO_REUSEADDR
     */
    public boolean getReuseAddress() throws SocketException {
        checkClosedAndCreate(true);
        return ((Boolean) impl.getOption(SocketOptions.SO_REUSEADDR))
                .booleanValue();
    }

    /**
     * Sets the state of the {@code SocketOptions.SO_OOBINLINE} for this socket.
     * When this option is enabled urgent data can be received in-line with
     * normal data.
     *
     * @param oobinline
     *            whether this option is enabled or not.
     * @throws SocketException
     *             if an error occurs while setting the option.
     * @see SocketOptions#SO_OOBINLINE
     */
    public void setOOBInline(boolean oobinline) throws SocketException {
        checkClosedAndCreate(true);
        impl.setOption(SocketOptions.SO_OOBINLINE, oobinline ? Boolean.TRUE
                : Boolean.FALSE);
    }

    /**
     * Gets the setting of the socket option {@code SocketOptions.SO_OOBINLINE}.
     *
     * @return {@code true} if the {@code SocketOptions.SO_OOBINLINE} is
     *         enabled, {@code false} otherwise.
     * @throws SocketException
     *             if an error occurs while reading the socket option.
     * @see SocketOptions#SO_OOBINLINE
     */
    public boolean getOOBInline() throws SocketException {
        checkClosedAndCreate(true);
        return ((Boolean) impl.getOption(SocketOptions.SO_OOBINLINE))
                .booleanValue();
    }

    /**
     * Sets the value of the {@code SocketOptions.IP_TOS} for this socket. See
     * the specification RFC 1349 for more information about the type of service
     * field.
     *
     * @param value
     *            the value to be set for this option with a valid range of
     *            {@code 0-255}.
     * @throws SocketException
     *             if an error occurs while setting the option.
     * @see SocketOptions#IP_TOS
     */
    public void setTrafficClass(int value) throws SocketException {
        checkClosedAndCreate(true);
        if (value < 0 || value > 255) {
            throw new IllegalArgumentException();
        }
        impl.setOption(SocketOptions.IP_TOS, Integer.valueOf(value));
    }

    /**
     * Gets the value of the socket option {@code SocketOptions.IP_TOS}.
     *
     * @return the value which represents the type of service.
     * @throws SocketException
     *             if an error occurs while reading the socket option.
     * @see SocketOptions#IP_TOS
     */
    public int getTrafficClass() throws SocketException {
        checkClosedAndCreate(true);
        return ((Number) impl.getOption(SocketOptions.IP_TOS)).intValue();
    }

    /**
     * Sends the given single byte data which is represented by the lowest octet
     * of {@code value} as "TCP urgent data".
     *
     * @param value
     *            the byte of urgent data to be sent.
     * @throws IOException
     *             if an error occurs while sending urgent data.
     */
    public void sendUrgentData(int value) throws IOException {
        if (!impl.supportsUrgentData()) {
            throw new SocketException("No urgent data support");
        }
        impl.sendUrgentData(value);
    }

    /**
     * Set the appropriate flags for a socket created by {@code
     * ServerSocket.accept()}.
     *
     * @see ServerSocket#implAccept
     */
    void accepted() {
        isCreated = isBound = isConnected = true;
    }

    /**
     * Gets the SocketChannel of this socket, if one is available. The current
     * implementation of this method returns always {@code null}.
     *
     * @return the related SocketChannel or {@code null} if no channel exists.
     */
    public SocketChannel getChannel() {
        return null;
    }

    /**
     * Sets performance preferences for connectionTime, latency and bandwidth.
     * <p>
     * This method does currently nothing.
     *
     * @param connectionTime
     *            the value representing the importance of a short connecting
     *            time.
     * @param latency
     *            the value representing the importance of low latency.
     * @param bandwidth
     *            the value representing the importance of high bandwidth.
     */
    public void setPerformancePreferences(int connectionTime, int latency,
            int bandwidth) {
        // Our socket implementation only provide one protocol: TCP/IP, so
        // we do nothing for this method
    }
}
