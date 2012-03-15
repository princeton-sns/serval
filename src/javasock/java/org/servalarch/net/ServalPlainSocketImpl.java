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

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketImpl;
import java.net.SocketOptions;
import java.net.SocketTimeoutException;
import java.security.AccessController;
import java.security.PrivilegedAction;

import org.servalarch.platform.ServalNetworkStack;

/**
 * A concrete connected-socket implementation.
 */
public class ServalPlainSocketImpl extends ServalSocketImpl {

    // Const copy from socket

    static final int MULTICAST_IF = 1;

    static final int MULTICAST_TTL = 2;

    static final int TCP_NODELAY = 4;

    static final int FLAG_SHUTDOWN = 8;

    private static Field fdField;

    private boolean tcpNoDelay = true;

    /**
     * used to store the trafficClass value which is simply returned as the
     * value that was set. We also need it to pass it to methods that specify an
     * address packets are going to be sent to
     */
    private int trafficClass;

    protected ServalNetworkStack netImpl = ServalNetworkStack.getInstance();

    public int receiveTimeout = 0;

    public boolean streaming = true;

    public boolean shutdownInput;

    Proxy proxy;

    public ServalPlainSocketImpl() {
        super();
        fd = new FileDescriptor();
    }

    public ServalPlainSocketImpl(FileDescriptor fd) {
        super();
        this.fd = fd;
    }

    /**
     * creates an instance with specified proxy.
     */
    public ServalPlainSocketImpl(Proxy proxy) {
        this();
        this.proxy = proxy;
    }
    

    public ServalPlainSocketImpl(FileDescriptor fd, ServiceID localServiceID, 
    		ServiceID remoteServiceID, InetAddress addr) {
        super();
        this.fd = fd;
        this.localServiceID = localServiceID;
        this.remoteServiceID = remoteServiceID;
        this.address = addr;
    }

    /*
    public ServalPlainSocketImpl(FileDescriptor fd, ServiceID localServiceID, InetAddress addr) {
        super();
        this.fd = fd;
        this.localServiceID = localServiceID;
        this.address = addr;
    }
     */
    @Override
    protected void accept(ServalSocketImpl newImpl) throws IOException {
    	/*
        if (NetUtil.usingSocks(proxy)) {
            ((ServalPlainSocketImpl) newImpl).socksBind();
            ((ServalPlainSocketImpl) newImpl).socksAccept();
            return;
        }
    	 */
        try {
            if (newImpl instanceof ServalPlainSocketImpl) {
                newImpl.fd = netImpl.accept(fd, newImpl, receiveTimeout);
            } else {
                // if newImpl is not an instance of PlainSocketImpl, use
                // reflection to get/set protected fields.
                if (null == fdField) {
                    fdField = getSocketImplField("fd");
                }
                FileDescriptor newFd = (FileDescriptor) fdField.get(newImpl);
                // call accept instead of acceptStreamImpl (native impl is identical)
                newFd = netImpl.accept(fd, newImpl, receiveTimeout);
                /*
                if (null == localportField) {
                    localportField = getSocketImplField("localport"); //$NON-NLS-1$
                }
                localportField.setInt(newImpl, getLocalPort());
                */
            }
        } catch (InterruptedIOException e) {
            throw new SocketTimeoutException(e.getMessage());
        } catch (IllegalAccessException e) {
            // empty
        }
    }

    /**
     * gets SocketImpl field by reflection.
     */
    private Field getSocketImplField(final String fieldName) {
        return AccessController.doPrivileged(new PrivilegedAction<Field>() {
            public Field run() {
                Field field = null;
                try {
                    field = SocketImpl.class.getDeclaredField(fieldName);
                    field.setAccessible(true);
                } catch (NoSuchFieldException e) {
                    throw new Error(e);
                }
                return field;
            }
        });
    }

    @Override
    protected synchronized int available() throws IOException {
        // we need to check if the input has been shutdown. If so
        // we should return that there is no data to be read
        if (shutdownInput == true) {
            return 0;
        }
        return netImpl.availableStream(fd);
    }

    @Override
    protected void bind(ServiceID localServiceID, InetAddress localAddr, 
    		int bindBits) throws IOException {
        netImpl.bind(fd, localServiceID, bindBits);
        // PlainSocketImpl2.socketBindImpl2(fd, aPort, anAddr);
        this.localServiceID = localServiceID;
        //this.localAddress = localAddr;
    }

    @Override
    protected void close() throws IOException {
        synchronized (fd) {
            if (fd.valid()) {
                if ((netImpl.getSocketFlags() & FLAG_SHUTDOWN) != 0) {
                    try {
                        shutdownOutput();
                    } catch (Exception e) {
                    }
                }
                netImpl.close(fd);
                fd = new FileDescriptor();
            }
        }
    }

    @Override
    protected void connect(String aService) throws IOException {
        connect(netImpl.getServiceByName(aService));
    }

    @Override
    protected void connect(ServiceID aService, InetAddress anAddr) 
        throws IOException {
        connect(aService, anAddr, -1);
    }

    /**
     * Connects this socket to the specified remote host address/port.
     *
     * @param aService
     * 			  the remote serviceID to connect to
     * @param anAddr
     *            the remote host address to connect to
     * @param timeout
     *            a timeout where supported. 0 means no timeout
     * @throws IOException
     *             if an error occurs while connecting
     */
	private void connect(ServiceID aService, InetAddress anAddr, int timeout)
            throws IOException {

        InetAddress normalAddr = null;
        
        if (anAddr != null)
            normalAddr = anAddr.isAnyLocalAddress() ? 
        		InetAddress.getLocalHost() : anAddr;
        
        try {
            netImpl.connect(fd, aService, normalAddr, timeout);
        } catch (ConnectException e) {
            throw new ConnectException(aService + ":" + anAddr + " - "
                    + e.getMessage());
        }
        super.address = normalAddr;
        super.remoteServiceID = aService;
    }

    @Override
    protected void create(boolean streaming) throws IOException {
        this.streaming = streaming;
        if (streaming) {
            netImpl.createStreamSocket(fd, 0);
        } else {
            netImpl.createDatagramSocket(fd, 0);
        }
    }

    @Override
    protected void finalize() throws IOException {
        close();
    }

    @Override
    protected synchronized InputStream getInputStream() throws IOException {
        if (!fd.valid()) {
            throw new SocketException("Invalid file descriptor");
        }

        return new ServalSocketInputStream(this);
    }

    @Override
    public Object getOption(int optID) throws SocketException {
        if (optID == SocketOptions.SO_TIMEOUT) {
            return Integer.valueOf(receiveTimeout);
        } else if (optID == SocketOptions.IP_TOS) {
            return Integer.valueOf(trafficClass);
        } else {
            // Call the native first so there will be
            // an exception if the socket if closed.
            Object result = netImpl.getOption(fd, optID);
            if (optID == SocketOptions.TCP_NODELAY
                    && (netImpl.getSocketFlags() & TCP_NODELAY) != 0) {
                return Boolean.valueOf(tcpNoDelay);
            }
            return result;
        }
    }

    @Override
    protected synchronized OutputStream getOutputStream() throws IOException {
        if (!fd.valid()) {
            throw new SocketException("Invalid file descriptor");
        }
        return new ServalSocketOutputStream(this);
    }

    @Override
    protected void listen(int backlog) throws IOException {
        /*
    	if (NetUtil.usingSocks(proxy)) {
            // Do nothing for a SOCKS connection. The listen occurs on the
            // server during the bind.
            return;
        }
        */
        netImpl.listen(fd, backlog);
    }

    @Override
    public void setOption(int optID, Object val) throws SocketException {
        if (optID == SocketOptions.SO_TIMEOUT) {
            receiveTimeout = ((Integer) val).intValue();
        } else {
            try {
                netImpl.setOption(fd, optID, val);
                if (optID == SocketOptions.TCP_NODELAY
                        && (netImpl.getSocketFlags() & TCP_NODELAY) != 0) {
                    tcpNoDelay = ((Boolean) val).booleanValue();
                }
            } catch (SocketException e) {
                // we don't throw an exception for IP_TOS even if the platform
                // won't let us set the requested value
                if (optID != SocketOptions.IP_TOS) {
                    throw e;
                }
            }

            /*
             * save this value as it is actually used differently for IPv4 and
             * IPv6 so we cannot get the value using the getOption. The option
             * is actually only set for IPv4 and a masked version of the value
             * will be set as only a subset of the values are allowed on the
             * socket. Therefore we need to retain it to return the value that
             * was set. We also need the value to be passed into a number of
             * natives so that it can be used properly with IPv6
             */
            if (optID == SocketOptions.IP_TOS) {
                trafficClass = ((Integer) val).intValue();
            }
        }
    }

    /**
     * Shutdown the input portion of the socket.
     */
    @Override
    protected void shutdownInput() throws IOException {
        shutdownInput = true;
        netImpl.shutdownInput(fd);
    }

    /**
     * Shutdown the output portion of the socket.
     */
    @Override
    protected void shutdownOutput() throws IOException {
        netImpl.shutdownOutput(fd);
    }

    @Override
    protected void connect(SocketAddress remoteAddr, int timeout)
            throws IOException {
        ServalSocketAddress servalAddr = (ServalSocketAddress) remoteAddr;
        connect(servalAddr.getServiceID(), servalAddr.getAddress(), timeout);
    }

    /**
     * Answer if the socket supports urgent data.
     */
    @Override
    protected boolean supportsUrgentData() {
        return !streaming || netImpl.supportsUrgentData(fd);
    }

    @Override
    protected void sendUrgentData(int value) throws IOException {
        netImpl.sendUrgentData(fd, (byte) value);
    }

    FileDescriptor getFD() {
        return fd;
    }

    @SuppressWarnings("unused")
	private void setLocalServiceID(ServiceID localServiceID) {
        this.localServiceID = localServiceID;
    }
    
    int read(byte[] buffer, int offset, int count) throws IOException {
        if (shutdownInput) {
            return -1;
        }
        int read = netImpl.read(fd, buffer, offset, count, receiveTimeout);
        // Return of zero bytes for a blocking socket means a timeout occurred
        if (read == 0) {
            throw new SocketTimeoutException();
        }
        // Return of -1 indicates the peer was closed
        if (read == -1) {
            shutdownInput = true;
        }
        return read;
    }

    int write(byte[] buffer, int offset, int count) throws IOException {
        if (!streaming) {
           /*
              return netImpl.sendDatagram2(fd, buffer, offset, count, port,
                    address);
           */
        	throw new IOException("Not implemented for non-streaming sockets");
        }
        return netImpl.write(fd, buffer, offset, count);
    }
}
