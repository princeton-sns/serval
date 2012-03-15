/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.net;

import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketOptions;
import java.net.InetAddress;
import java.io.IOException;
import java.nio.channels.DatagramChannel;
import org.servalarch.net.ServalDatagramSocketImpl;
import org.servalarch.net.ServiceID;
import org.servalarch.net.ServalDatagramSocketImplFactory;

/*
  This code is based on the DatagramSocket implementation from the
  Harmony project.
 */

/**
 * This class implements a Serval datagram socket for sending and
 * receiving {@code ServalDatagramPacket}. A {@code ServalDatagramSocket}
 * object can be used for both endpoints of a connection for a packet
 * delivery service.
 *
 * @see ServalDatagramPacket
 * @see ServalDatagramSocketImplFactory
 */
public class ServalDatagramSocket {

    ServalDatagramSocketImpl impl;

    InetAddress address;

    ServiceID serviceID;
    static ServalDatagramSocketImplFactory factory;

    boolean isBound = false;

    private boolean isConnected = false;

    private boolean isClosed = false;

    private static class Lock {
    }

    private Object lock = new Lock();

    /**
     * Constructs a Serval datagram socket which is bound to any
     * available serviceID on the localhost.
     *
     * @throws SocketException
     *             if an error occurs while creating or binding the socket.
     */
    public ServalDatagramSocket() throws SocketException {
        this(new ServiceID(0));
    }

    /**
     * Constructs a Serval datagram socket which is bound to the
     * specific serviceID {@code aServiceID} on the localhost.
     *
     * @param serviceID
     *            the serviceID to bind on the localhost.
     * @throws SocketException
     *             if an error occurs while creating or binding the socket.
     */
    public ServalDatagramSocket(ServiceID serviceID) 
        throws SocketException {
        checkListen(serviceID);
        createSocket(serviceID, null, 0);
    }

    /**
     * Constructs a Serval datagram socket which is bound to the
     * specific serviceID {@code aServiceID} on the localhost.
     *
     * @param serviceID
     *            the serviceID to bind on the localhost.
     * @param bindBits
     *            the number of bits to bind on in the ServiceID (0 = all).
     * @throws SocketException
     *             if an error occurs while creating or binding the socket.
     */
    public ServalDatagramSocket(ServiceID serviceID, int bindBits) 
        throws SocketException {
        checkListen(serviceID);
        createSocket(serviceID, null, bindBits);
    }

    /**
     * Constructs a Serval datagram socket which is bound to the
     * specific local serviceID {@code serviceID} and address {@code
     * addr}.
     *
     * @param serviceID
     *            the serviceID to bind on the localhost.
     * @param addr
     *            the address to bind on the localhost.
     * @throws SocketException
     *             if an error occurs while creating or binding the socket.
     */
    public ServalDatagramSocket(ServiceID serviceID, InetAddress addr) 
        throws SocketException {
        checkListen(serviceID);
        createSocket(serviceID, addr, 0);
    }

    /**
     * Sends prior to attempting to bind the socket.
     *
     * @param serviceID
     *            the serviceID on the localhost that is to be bound.
     */
    void checkListen(ServiceID serviceID) {
        if (!serviceID.valid()) {
            throw new IllegalArgumentException();
        }
        /*
        SecurityManager security = System.getSecurityManager();
        if (security != null) {
            security.checkListen(serviceID);
        }
        */
    }

    /**
     * Closes this Serval datagram socket and all possibly associated channels.
     */
    // In the documentation jdk1.1.7a/guide/net/miscNet.html, this method is
    // noted as not being synchronized.
    public void close() {
        isClosed = true;
        impl.close();
    }

    /**
     * Connects this Serval datagram socket to the specific target
     * host with the serviceID {@code aServiceID} and address 
     * {@code anAdress}.
     *
     * @param aServiceID
     *            the target serviceID of this socket.
     * @param anAddress
     *            the target address of this socket.
     * @param timeout
     *            the timeout for connecting (negative = infinite).
     */
    public void connect(ServiceID aServiceID, InetAddress anAddress,
                        int timeout) throws SocketException {
        if (aServiceID == null || !aServiceID.valid()) {
            throw new IllegalArgumentException();
        }

        synchronized (lock) {
            if (isClosed()) {
                return;
            }
            try {
                checkClosedAndBind(true);
            } catch (SocketException e) {
                // Ignored
            }
            /*
            SecurityManager security = System.getSecurityManager();
            if (security != null) {
                if (anAddress.isMulticastAddress()) {
                    security.checkMulticast(anAddress);
                } else {
                    security.checkConnect(anAddress.getHostName(), aPort);
                }
            }
            */

            try {
                impl.connect(aServiceID, anAddress, timeout);
            } catch (SocketException e) {
                throw e;
            }
            serviceID = aServiceID;
            address = anAddress;
            isConnected = true;
        }
    }

    /**
     * Connects this datagram socket to the remote serviceID specified
     * by {@code remoteAddr}. The serviceID is validated, thereafter
     * the only validation on {@code send()} and {@code receive()} is
     * that the packet serviceID matches the connected target.
     *
     * @param remoteAddr
     *            the serviceID of the target host.
     * @param timeout
     *            the timeout for connecting (negative = infinite).
     * @throws SocketException
     *                if an error occurs during connecting.
     */
    public void connect(SocketAddress remoteAddr, int timeout) 
        throws SocketException {
        if (remoteAddr == null) {
            throw new IllegalArgumentException();
        }

        if (!(remoteAddr instanceof ServalSocketAddress)) {
            throw new IllegalArgumentException("Not a Serval socket address");
        }

        ServalSocketAddress servalAddr = (ServalSocketAddress) remoteAddr;
        if (servalAddr.getServiceID() == null) {
            throw new SocketException(servalAddr.getHostName());
        }
        connect(servalAddr.getServiceID(), servalAddr.getAddress(), timeout);
    }

    /**
     * Connects this datagram socket to the remote serviceID specified
     * by {@code remoteAddr}. The serviceID is validated, thereafter
     * the only validation on {@code send()} and {@code receive()} is
     * that the packet serviceID matches the connected target.
     *
     * @param remoteAddr
     *            the serviceID of the target host.
     * @throws SocketException
     *                if an error occurs during connecting.
     */
    public void connect(SocketAddress remoteAddr) throws SocketException {
        connect(remoteAddr, -1);
    }

    public void connect(ServiceID aServiceID) throws SocketException {
        connect(aServiceID, null, -1);
    }

    public void connect(ServiceID aServiceID, int timeout) 
        throws SocketException {
        connect(aServiceID, null, timeout);
    }
    /**
     * Disconnects this Serval datagram socket from the remote
     * host. This method called on an unconnected socket does nothing.
     */
    public void disconnect() {
        if (isClosed() || !isConnected()) {
            return;
        }
        impl.disconnect();
        serviceID = null;
        address = null;
        isConnected = false;
    }

    synchronized void createSocket(ServiceID serviceID, InetAddress addr, 
                                   int bindBits)
            throws SocketException {
        impl = factory != null ? factory.createServalDatagramSocketImpl()
            : new ServalDatagramSocketImpl();
        impl.create();
        try {
            impl.bind(serviceID, addr, bindBits);
            isBound = true;
        } catch (SocketException e) {
            close();
            throw e;
        }
    }

    /**
     * Gets the {@code InetAddress} instance representing the remote address to
     * which this Serval datagram socket is connected.
     *
     * @return the remote address this socket is connected to or
     *         {@code null} if this socket is not connected.
     */
    public InetAddress getInetAddress() {
        return address;
    }

    /**
     * Gets the {@code InetAddress} instance representing the bound local
     * address of this Serval datagram socket.
     *
     * @return the local address to which this socket is bound to or {@code
     *         null} if this socket is closed.
     */
    public InetAddress getLocalAddress() {
        if (isClosed()) {
            return null;
        }
        if (!isBound()) {
            return null;
        }
        InetAddress anAddr = impl.getLocalAddress();
        try {
            SecurityManager security = System.getSecurityManager();
            if (security != null) {
                security.checkConnect(anAddr.getHostName(), -1);
            }
        } catch (SecurityException e) {
            return null;
        }
        return anAddr;
    }

    /**
     * Gets the local serviceID which this socket is bound to.
     *
     * @return the local serviceID of this socket or {@code null} if
     *         this socket is closed and an invalid serviceID if it is
     *         unbound.
     */
    public ServiceID getLocalServiceID() {
        if (isClosed()) {
            return null;
        }
        if (!isBound()) {
            return null;
        }
        return impl.getLocalServiceID();
    }

    /**
     * Gets the remote serviceID which this socket is connected to.
     *
     * @return the remote serviceID of this socket. The return value
     *         {@code null} indicates that this socket is not
     *         connected.
     */
    public ServiceID getServiceID() {
        return serviceID;
    }

    /**
     * Indicates whether this socket is multicast or not.
     *
     * @return the return value is always {@code false}.
     */
    boolean isMulticastSocket() {
        return false;
    }

    /**
     * Gets the socket receive buffer size. ( {@code SocketOptions.SO_RCVBUF} )
     *
     * @return the input buffer size.
     * @throws SocketException
     *                if an error occurs while getting the option value.
     */
    public synchronized int getReceiveBufferSize() throws SocketException {
        checkClosedAndBind(false);
        return ((Integer) impl.getOption(SocketOptions.SO_RCVBUF)).intValue();
    }

    /**
     * Gets the socket send buffer size. ( {@code SocketOptions.SO_SNDBUF} )
     *
     * @return the output buffer size.
     * @throws SocketException
     *                if an error occurs while getting the option value.
     */
    public synchronized int getSendBufferSize() throws SocketException {
        checkClosedAndBind(false);
        return ((Integer) impl.getOption(SocketOptions.SO_SNDBUF)).intValue();
    }

    /**
     * Gets the socket receive timeout in milliseconds. The return value {@code
     * 0} implies the timeout is disabled/infinitive. ( {@code
     * SocketOptions.SO_TIMEOUT} )
     *
     * @return the socket receive timeout.
     * @throws SocketException
     *                if an error occurs while getting the option value.
     */
    public synchronized int getSoTimeout() throws SocketException {
        checkClosedAndBind(false);
        return ((Integer) impl.getOption(SocketOptions.SO_TIMEOUT)).intValue();
    }

    /**
     * Receives a packet from this socket and stores it in the argument {@code
     * pack}. All fields of {@code pack} must be set according to the data
     * received. If the received data is longer than the packet buffer size it
     * is truncated. This method blocks until a packet is received or a timeout
     * has expired. If a security manager exists, its {@code checkAccept} method
     * determines whether or not a packet is discarded. Any packets from
     * unacceptable origins are silently discarded.
     *
     * @param pack
     *            the {@code ServalDatagramPacket} to store the received data.
     * @throws IOException
     *                if an error occurs while receiving the packet.
     */
    public synchronized int receive(ServalDatagramPacket pack) 
        throws IOException, IllegalArgumentException {
        int ret = 0;

        //checkClosedAndBind(true);
        checkClosedAndBind(false);

        ServiceID senderServiceID;
        InetAddress senderAddr;
        ServalDatagramPacket tempPack = new ServalDatagramPacket(new byte[1], 1);

        // means that we have received the packet into the temporary buffer
        boolean copy = false;
        
        SecurityManager security = System.getSecurityManager();

        if (serviceID != null || security != null) {
            // The socket is connected or we need to check security
            // permissions

            // Check pack before peeking
            if (pack == null) {
                throw new NullPointerException();
            }
        
            // iterate over incoming packets
            while (true) {
                copy = false;

                // let's get sender's serviceID and address
                try {
                    impl.peekData(tempPack);
                    SocketAddress sa = tempPack.getSocketAddress();

                    if (!(sa instanceof ServalSocketAddress)) {
                        throw new IllegalArgumentException("Bad socket address");
                    }

                    ServalSocketAddress ssa = (ServalSocketAddress)sa;
                    senderServiceID = ssa.getServiceID();

                    senderAddr = tempPack.getAddress();
                } catch (SocketException e) {
                    if (e.getMessage().equals(
                            "The socket does not support the operation")) {
                        // receive packet to temporary buffer
                        tempPack = new ServalDatagramPacket(
                            new byte[pack.getData().length],
                            pack.getData().length);
                        impl.receive(tempPack);
                        // tempPack's length field is now updated,
                        // capacity is unchanged let's extract
                        // serviceID and address
                        SocketAddress sa = tempPack.getSocketAddress();
                        
                        if (!(sa instanceof ServalSocketAddress)) {
                            throw new IllegalArgumentException("Bad socket address");
                        }

                        ServalSocketAddress ssa = (ServalSocketAddress)sa;
                        senderServiceID = ssa.getServiceID();
                        senderAddr = tempPack.getAddress();
                        copy = true;
                    } else {
                        throw e;
                    }
                }

                if (serviceID == null) {
                    /*
                    // if we are not connected let's check if we are allowed to
                    // receive packets from sender's address and port
                    try {
                        security.checkAccept(senderAddr.getHostName(),
                                senderPort);
                        // address & port are valid
                        break;
                    } catch (SecurityException e) {
                        if (!copy) {
                            // drop this packet and continue
                            impl.receive(tempPack);
                        }
                    }
                    */
                    break;
                } else if (serviceID.equals(senderServiceID) && 
                           (address == null || address.equals(senderAddr))) {
                    // we are connected and the packet came
                    // from the serviceID and address we are connected to
                    break;
                } else if (!copy) {
                    // drop packet and continue
                    ret = impl.receive(tempPack);
                }
            }
        }

        if (copy) {
            System.arraycopy(tempPack.getData(), 0, pack.getData(), 
                             pack.getOffset(), tempPack.getLength());
            // we shouldn't update the pack's capacity field in order to be
            // compatible with RI
            pack.setLength(tempPack.getLength());
            pack.setServiceID(tempPack.getServiceID());
            pack.setAddress(tempPack.getAddress());
        } else {
            pack.setLength(pack.getData().length);
            ret = impl.receive(pack);
            // pack's length field is now updated by native code call;
            // pack's capacity field is unchanged
        }
        return ret;
    }

    /**
     * Sends a packet over this socket. The packet must satisfy the security
     * policy before it may be sent. If a security manager is installed, this
     * method checks whether it is allowed to send this packet to the specified
     * address.
     *
     * @param pack
     *            the {@code ServalDatagramPacket} which has to be sent.
     * @throws IOException
     *                if an error occurs while sending the packet.
     */
    public void send(ServalDatagramPacket pack) throws IOException {
        //checkClosedAndBind(true);
        checkClosedAndBind(false);

        InetAddress packAddr = pack.getAddress();
        SocketAddress sa;
        
        if (isConnected) {
            sa = new ServalSocketAddress(serviceID);
        } else {
            sa = pack.getSocketAddress();
        }

        if (!(sa instanceof ServalSocketAddress)) {
            throw new IllegalArgumentException("Bad socket address");
        }
        ServalSocketAddress ssa = (ServalSocketAddress)sa;
        ServiceID packServiceID = ssa.getServiceID();

        if (isConnected) {
            if (packServiceID != null) {
                if (serviceID != null && !serviceID.equals(packServiceID)) {
                    throw new IllegalArgumentException("Invalid destination serviceID");
                }
            } else {
                pack.setSocketAddress(new ServalSocketAddress(serviceID));
            }
            if (packAddr != null) {
                if (!address.equals(packAddr)) {
                    throw new IllegalArgumentException("Invalid destination address");
                }
            } else {
                pack.setAddress(address);
            }
        } else {
            // not connected so the target address is not allowed to be null
            if (packServiceID == null) {
                // KA019 Destination address is null
                throw new NullPointerException("No destination serviceID");
            }

            if (!packServiceID.valid()) {
                throw new IllegalArgumentException("Invalid serviceID");
            }
            /*
            SecurityManager security = System.getSecurityManager();
            if (security != null) {
                if (packAddr.isMulticastAddress()) {
                    security.checkMulticast(packAddr);
                } else {
                    security.checkConnect(packAddr.getHostName(), pack
                            .getPort());
                }
            }
            */
        }
        impl.send(pack);
    }

    /**
     * Sets the socket send buffer size. This buffer size determines which the
     * maximum packet size is that can be sent over this socket. It depends on
     * the network implementation what will happen if the packet is bigger than
     * the buffer size. ( {@code SocketOptions.SO_SNDBUF} )
     *
     * @param size
     *            the buffer size in bytes. The size must be at least one byte.
     * @throws SocketException
     *                if an error occurs while setting the option.
     */
    public synchronized void setSendBufferSize(int size) throws SocketException {
        if (size < 1) {
            throw new IllegalArgumentException();
        }
        checkClosedAndBind(false);
        impl.setOption(SocketOptions.SO_SNDBUF, Integer.valueOf(size));
    }

    /**
     * Sets the socket receive buffer size. This buffer size determines which
     * the maximum packet size is that can be received over this socket. It
     * depends on the network implementation what will happen if the packet is
     * bigger than the buffer size. ( {@code SocketOptions.SO_RCVBUF} )
     *
     * @param size
     *            the buffer size in bytes. The size must be at least one byte.
     * @throws SocketException
     *                if an error occurs while setting the option.
     */
    public synchronized void setReceiveBufferSize(int size)
            throws SocketException {
        if (size < 1) {
            throw new IllegalArgumentException();
        }
        checkClosedAndBind(false);
        impl.setOption(SocketOptions.SO_RCVBUF, Integer.valueOf(size));
    }

    /**
     * Sets the timeout period in milliseconds for the {@code receive()} method.
     * This receive timeout defines the period the socket will block waiting to
     * receive data before throwing an {@code InterruptedIOException}. The value
     * {@code 0} (default) is used to set an infinite timeout. To have effect
     * this option must be set before the blocking method was called. ( {@code
     * SocketOptions.SO_TIMEOUT} )
     *
     * @param timeout
     *            the timeout period in milliseconds or {@code 0} for infinite.
     * @throws SocketException
     *                if an error occurs while setting the option.
     */
    public synchronized void setSoTimeout(int timeout) throws SocketException {
        if (timeout < 0) {
            throw new IllegalArgumentException();
        }
        checkClosedAndBind(false);
        impl.setOption(SocketOptions.SO_TIMEOUT, Integer.valueOf(timeout));
    }

    /**
     * Sets the socket implementation factory. This may only be invoked once
     * over the lifetime of the application. This factory is used to create
     * a new datagram socket implementation. If a security manager is set its
     * method {@code checkSetFactory()} is called to check if the operation is
     * allowed. A {@code SecurityException} is thrown if the operation is not
     * allowed.
     *
     * @param fac
     *            the socket factory to use.
     * @throws IOException
     *                if the factory has already been set.
     * @see ServalDatagramSocketImplFactory
     */
    public static synchronized void setServalDatagramSocketImplFactory(
            ServalDatagramSocketImplFactory fac) throws IOException {
        /*
        SecurityManager security = System.getSecurityManager();
        if (security != null) {
            security.checkSetFactory();
        }
        */
        if (factory != null) {
            throw new SocketException();
        }
        factory = fac;
    }

    /**
     * Constructs a new {@code ServalDatagramSocket} using the specific datagram
     * socket implementation {@code socketImpl}. The created {@code
     * ServalDatagramSocket} will not be bound.
     *
     * @param socketImpl
     *            the ServalDatagramSocketImpl to use.
     */
    protected ServalDatagramSocket(ServalDatagramSocketImpl socketImpl) {
        if (socketImpl == null) {
            throw new NullPointerException();
        }
        impl = socketImpl;
        isClosed = false;
        isConnected = true;
    }

    /**
     * Constructs a new {@code ServalDatagramSocket} bound to the
     * serviceID specified by the {@code SocketAddress} {@code
     * localAddr} or an unbound {@code ServalDatagramSocket} if the
     * {@code SocketAddress} is {@code null}.
     *
     * @param localAddr
     *            the local machine serviceID to bind to.
     * @throws IllegalArgumentException
     *             if the SocketAddress is not supported
     * @throws SocketException
     *             if a problem occurs creating or binding the socket.
     */
    public ServalDatagramSocket(SocketAddress localAddr) throws SocketException {
        if (localAddr != null) {
            if (!(localAddr instanceof ServalSocketAddress)) {
                throw new IllegalArgumentException("Not Serval socket address");
            }
            checkListen(((ServalSocketAddress) localAddr).getServiceID());
        }
        impl = factory != null ? factory.createServalDatagramSocketImpl()
            : new ServalDatagramSocketImpl();
        impl.create();
        if (localAddr != null) {
            try {
                bind(localAddr);
            } catch (SocketException e) {
                close();
                throw e;
            }
        }
        // SocketOptions.SO_BROADCAST is set by default for ServalDatagramSocket
        setBroadcast(true);
    }

    void checkClosedAndBind(boolean bind) throws SocketException {
        if (isClosed()) {
            System.out.println("socket closed");
        
            throw new SocketException();
        }
        if (bind && !isBound()) {
            checkListen(null);
            impl.bind(null, null);
            isBound = true;
        }
    }

    /**
     * Binds this socket to the local serviceID specified by {@code
     * localAddr}. If this value is {@code null} any free serviceID is
     * used.
     *
     * @param localAddr
     *            the local machine serviceID to bind on.
     * @throws IllegalArgumentException
     *             if the SocketAddress is not supported
     * @throws SocketException
     *             if the socket is already bound or a problem occurs during
     *             binding.
     */
    public void bind(SocketAddress localAddr) throws SocketException {
        checkClosedAndBind(false);
        InetAddress addr = null;
        // Should probably use a ServalServiceID.ANY here:
        ServiceID localServiceID = null;
        if (localAddr != null) {
            if (!(localAddr instanceof ServalSocketAddress)) {
                throw new IllegalArgumentException("Not a Serval socket address");
            }
            ServalSocketAddress servalAddr = (ServalSocketAddress) localAddr;
            localServiceID = servalAddr.getServiceID();

            if (localServiceID == null) {
                throw new SocketException(servalAddr.getHostName());
            }
            
            addr = servalAddr.getAddress();

            checkListen(localServiceID);
        }
        impl.bind(localServiceID, addr);
        isBound = true;
    }

    /**
     * Determines whether the socket is bound to an address or not.
     *
     * @return {@code true} if the socket is bound, {@code false} otherwise.
     */
    public boolean isBound() {
        return isBound;
    }

    /**
     * Determines whether the socket is connected to a target host.
     *
     * @return {@code true} if the socket is connected, {@code false} otherwise.
     */
    public boolean isConnected() {
        return isConnected;
    }

    /**
     * Gets the serviceID and address of the connected remote host. If
     * this socket is not connected yet, {@code null} is returned.
     *
     * @return the remote socket address.
     */
    public SocketAddress getRemoteSocketAddress() {
        if (!isConnected()) {
            return null;
        }
        return new ServalSocketAddress(getServiceID(), getInetAddress());
    }

    /**
     * Gets the bound local serviceID and address of this socket. If
     * the socket is unbound, {@code null} is returned.
     *
     * @return the local socket address.
     */
    public SocketAddress getLocalSocketAddress() {
        if (!isBound()) {
            return null;
        }
        return new ServalSocketAddress(getLocalServiceID(), getLocalAddress());
    }

    /**
     * Sets the socket option {@code SocketOptions.SO_REUSEADDR}. This option
     * has to be enabled if more than one UDP socket wants to be bound to the
     * same address. That could be needed for receiving multicast packets.
     * <p>
     * There is an undefined behavior if this option is set after the socket is
     * already bound.
     *
     * @param reuse
     *            the socket option value to enable or disable this option.
     * @throws SocketException
     *             if the socket is closed or the option could not be set.
     */
    public void setReuseAddress(boolean reuse) throws SocketException {
        checkClosedAndBind(false);
        impl.setOption(SocketOptions.SO_REUSEADDR, reuse ? Boolean.TRUE
                : Boolean.FALSE);
    }

    /**
     * Gets the state of the socket option {@code SocketOptions.SO_REUSEADDR}.
     *
     * @return {@code true} if the option is enabled, {@code false} otherwise.
     * @throws SocketException
     *             if the socket is closed or the option is invalid.
     */
    public boolean getReuseAddress() throws SocketException {
        checkClosedAndBind(false);
        return ((Boolean) impl.getOption(SocketOptions.SO_REUSEADDR))
                .booleanValue();
    }

    /**
     * Sets the socket option {@code SocketOptions.SO_BROADCAST}. This option
     * must be enabled to send broadcast messages.
     *
     * @param broadcast
     *            the socket option value to enable or disable this option.
     * @throws SocketException
     *             if the socket is closed or the option could not be set.
     */
    public void setBroadcast(boolean broadcast) throws SocketException {
        checkClosedAndBind(false);
        impl.setOption(SocketOptions.SO_BROADCAST, broadcast ? Boolean.TRUE
                : Boolean.FALSE);
    }

    /**
     * Gets the state of the socket option {@code SocketOptions.SO_BROADCAST}.
     *
     * @return {@code true} if the option is enabled, {@code false} otherwise.
     * @throws SocketException
     *             if the socket is closed or the option is invalid.
     */
    public boolean getBroadcast() throws SocketException {
        checkClosedAndBind(false);
        return ((Boolean) impl.getOption(SocketOptions.SO_BROADCAST))
                .booleanValue();
    }

    /**
     * Sets the socket option {@code SocketOptions.IP_TOS}. This option defines
     * the value of the type-of-service field of the IP-header for every packet
     * sent by this socket. The value could be ignored by the underlying network
     * implementation.
     * <p>
     * Values between {@code 0} and {@code 255} inclusive are valid for this
     * option.
     *
     * @param value
     *            the socket option value to be set as type-of-service.
     * @throws SocketException
     *             if the socket is closed or the option could not be set.
     */
    public void setTrafficClass(int value) throws SocketException {
        checkClosedAndBind(false);
        if (value < 0 || value > 255) {
            throw new IllegalArgumentException();
        }
        impl.setOption(SocketOptions.IP_TOS, Integer.valueOf(value));
    }

    /**
     * Gets the value of the type-of-service socket option {@code
     * SocketOptions.IP_TOS}.
     *
     * @return the type-of-service socket option value.
     * @throws SocketException
     *             if the socket is closed or the option is invalid.
     */
    public int getTrafficClass() throws SocketException {
        checkClosedAndBind(false);
        return ((Number) impl.getOption(SocketOptions.IP_TOS)).intValue();
    }

    /**
     * Gets the state of this socket.
     *
     * @return {@code true} if the socket is closed, {@code false} otherwise.
     */
    public boolean isClosed() {
        return isClosed;
    }

    /**
     * Gets the related DatagramChannel of this socket. This implementation
     * returns always {@code null}.
     *
     * @return the related DatagramChannel or {@code null} if this socket was
     *         not created by a {@code DatagramChannel} object.
     */
    public DatagramChannel getChannel() {
        return null;
    }
}
