/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.net;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketOptions;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import org.servalarch.platform.ServalNetworkStack;

/**
 * The superclass for Serval datagram socket implementations.
 */
public class ServalDatagramSocketImpl implements SocketOptions {

    /**
     * File descriptor that is used to address this socket.
     */
    private FileDescriptor fd;

    /**
     * Constructs an unbound datagram socket implementation.
     */
    //public ServalDatagramSocketImpl() {
	//    localServiceID = null;
    //}
    static final int TCP_NODELAY = 4;

    static final int FLAG_SHUTDOWN = 8;
    private final static int SO_BROADCAST = 32;

    /**
     * for datagram and multicast sockets we have to set REUSEADDR and REUSEPORT
     * when REUSEADDR is set for other types of sockets we need to just set
     * REUSEADDR therefore we have this other option which sets both if
     * supported by the platform. this cannot be in SOCKET_OPTIONS because since
     * it is a public interface it ends up being public even if it is not
     * declared public
     */
    static final int REUSEADDR_AND_REUSEPORT = 10001;

    // Ignored in native code
    private boolean bindToDevice = false;

    private volatile boolean isNativeConnected;

    private ServalNetworkStack netImpl = ServalNetworkStack.getInstance();

    public int receiveTimeout;

    public boolean streaming = true;

    public boolean shutdownInput;

    private ServiceID localServiceID = null;
    private InetAddress localAddress = null;
    /**
     * The number of the local serviceID to which this socket is
     * connected to at the native level.
     */
    private ServiceID connectedServiceID = null;
    /**
     * used to keep address to which the socket was connected to at
     * the native level
     */
    private InetAddress connectedAddress = null;

    /**
     * used to store the trafficClass value which is simply returned as the
     * value that was set. We also need it to pass it to methods that specify an
     * address packets are going to be sent to
     */
    private int trafficClass;

    public ServalDatagramSocketImpl(FileDescriptor fd, 
                                    ServiceID localServiceID) {
        this.fd = fd;
        this.localServiceID = localServiceID;
    }
    
    public ServalDatagramSocketImpl(FileDescriptor fd) {
        this.fd = fd;
        /* FileDescriptor should already be bound, retreive the bound
         * serviceID */
        this.localServiceID = netImpl.getSocketLocalServiceID(fd);
    }

    public ServalDatagramSocketImpl() {
        fd = new FileDescriptor();
    }

    public void bind(ServiceID serviceID, InetAddress addr, int bindBits) 
        throws SocketException {
        //prop != null && prop.toLowerCase().equals("true"); //$NON-NLS-1$
        netImpl.bind(fd, serviceID, bindBits);
        if (serviceID != null) {
            localServiceID = serviceID;
        } else {
            localServiceID = netImpl.getSocketLocalServiceID(fd);
        }

        try {
            // Ignore failures
            setOption(SO_BROADCAST, Boolean.TRUE);
        } catch (IOException e) {
        }
    }

    public void bind(ServiceID serviceID, int bindBits) 
        throws SocketException {

        // FIXME: Should implement IP address binding
        bind(serviceID, null, bindBits);
    }

    public void bind(ServiceID serviceID) 
        throws SocketException {

        // FIXME: Should implement IP address binding
        bind(serviceID, null, 0);
    }

    public void bind(ServiceID serviceID, InetAddress addr) 
        throws SocketException {

        // FIXME: Should implement IP address binding
        bind(serviceID, null, 0);
    }

    protected void listen(int backlog) throws IOException
    {
        if (fd == null) {
            throw new IOException("socket not created");
        }

        netImpl.listen(fd, backlog);
    }

    /**
     * Accepts a new connection to the socket. Blocks until a new
     * connection arrives.
     *
     * @param s a socket that will be used to represent the new connection.
     * @throws IOException
     */
    protected void accept(ServalDatagramSocketImpl s) throws IOException
    {
        if (fd == null) {
            throw new IOException("socket not created");
        }

        FileDescriptor clientFd = netImpl.accept(fd, s, 0);

        if (clientFd == null) {
            throw new IOException("client socket not created");
        }
        s.fd = clientFd;
        s.isNativeConnected = true;
    }

    public void close() {
        synchronized (fd) {
            if (fd.valid()) {
                try {
                    netImpl.close(fd);
                } catch (IOException e) {
                }
                fd = new FileDescriptor();
            }
        }
    }

    public void create() throws SocketException {
        netImpl.createDatagramSocket(fd, 0);
    }

    protected void finalize() {
        close();
    }

    public Object getOption(int optID) throws SocketException {
        if (optID == SocketOptions.SO_TIMEOUT) {
            return Integer.valueOf(receiveTimeout);
        } else if (optID == SocketOptions.IP_TOS) {
            return Integer.valueOf(trafficClass);
        } else {
            // Call the native first so there will be
            // an exception if the socket if closed.
            Object result = getSocketOption(optID);
            /*
            if (optID == SocketOptions.IP_MULTICAST_IF
                    && (netImpl.getSocketFlags() & MULTICAST_IF) != 0) {
                try {
                    return InetAddress.getByAddress(ipaddress);
                } catch (UnknownHostException e) {
                    return null;
                }
            }
            */
            return result;
        }
    }
    
    public int receive(ServalDatagramPacket pack) throws java.io.IOException {
        int ret = 0;

        try {
            if (isNativeConnected) {
                // do not peek
                ret = netImpl.recvConnectedDatagram(fd, pack, 
                                                    pack.getData(), 
                                                    pack.getOffset(), 
                                                    pack.getLength(), 
                                                    receiveTimeout, false);
                updatePacketRecvAddress(pack);
            } else {
                // receiveDatagramImpl2
                /*
                ret = netImpl.receiveDatagram(fd, pack, 
                pack.getData(), 
                pack.getOffset(), 
                pack.getLength(), 
                receiveTimeout, false);
                */
            }
        } catch (InterruptedIOException e) {
            throw new SocketTimeoutException(e.getMessage());
        }
        return ret;
    }

    public void send(ServalDatagramPacket packet) throws IOException {
        if (isNativeConnected) {
            netImpl.sendConnectedDatagram(fd, packet.getData(), 
                                          packet.getOffset(), 
                                          packet.getLength(), 
                                          bindToDevice);
        } else {
            // sendDatagramImpl2
            /*
            netImpl.sendDatagram(fd, packet.getData(),
                               packet.getOffset(), 
                               packet.getLength(),
                               packet.getPort(), 
                               bindToDevice, 
                               trafficClass, 
                               packet.getAddress());
            */
        }
    }

    /**
     * Set the nominated socket option. As the timeouts are not set as options
     * in the IP stack, the value is stored in an instance field.
     * 
     * @throws SocketException thrown if the option value is unsupported or
     *         invalid
     */
    public void setOption(int optID, Object val) throws SocketException {
        /*
         * for datagram sockets on some platforms we have to set both the
         * REUSEADDR AND REUSEPORT so for REUSEADDR set this option option which
         * tells the VM to set the two values as appropriate for the platform
         */
        if (optID == SocketOptions.SO_REUSEADDR) {
            optID = REUSEADDR_AND_REUSEPORT;
        }

        if (optID == SocketOptions.SO_TIMEOUT) {
            receiveTimeout = ((Integer) val).intValue();
        } else {
            int flags = netImpl.getSocketFlags();
            try {
                setSocketOption(optID | (flags << 16), val);
            } catch (SocketException e) {
                // we don't throw an exception for IP_TOS even if the platform
                // won't let us set the requested value
                if (optID != SocketOptions.IP_TOS) {
                    throw e;
                }
            }
            /*
            if (optID == SocketOptions.IP_MULTICAST_IF && (flags & MULTICAST_IF) != 0) {
                InetAddress inet = (InetAddress) val;
                if (NetUtil.bytesToInt(inet.getAddress(), 0) == 0 || inet.isLoopbackAddress()) {
                    ipaddress = ((InetAddress) val).getAddress();
                } else {
                    InetAddress local = null;
                    try {
                        local = InetAddress.getLocalHost();
                    } catch (UnknownHostException e) {
                        throw new SocketException("getLocalHost(): " + e.toString());
                    }
                    if (inet.equals(local)) {
                        ipaddress = ((InetAddress) val).getAddress();
                    } else {
                        throw new SocketException(val + " != getLocalHost(): " + local);
                    }
                }
            }
            */
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
    public void connect(ServiceID serviceID, InetAddress inetAddr, 
                        int timeout)
        throws SocketException {
        
        netImpl.connect(fd, serviceID, inetAddr, timeout);
        connectedServiceID = serviceID;
        isNativeConnected = true;
    }
    public void connect(ServiceID serviceID, int timeout) 
        throws SocketException {
        connect(serviceID, null, timeout);        
    }

    public void disconnect() {
        try {
            netImpl.disconnect(fd);
        } catch (Exception e) {
            // there is currently no way to return an error so just eat any
            // exception
        }
        connectedServiceID = null;
        connectedAddress = null;
        isNativeConnected = false;
    }

    public int peekData(ServalDatagramPacket pack) throws IOException {
        try {
            if (isNativeConnected) {
                netImpl.recvConnectedDatagram(fd, pack, 
                                              pack.getData(), 
                                              pack.getOffset(), 
                                              pack.getLength(), 
                                              receiveTimeout, true); // peek
                updatePacketRecvAddress(pack);
            } else {
                /*
                netImpl.receiveDatagram(fd, pack, 
                                      pack.getData(), 
                                      pack.getOffset(), 
                                      pack.getLength(), 
                                      receiveTimeout, true); // peek
                */
                return -1;
            }
        } catch (InterruptedIOException e) {
            throw new SocketTimeoutException(e.toString());
        }
        return 0;
    }

    /**
     * Set the received address and port in the packet. We do this when the
     * Datagram socket is connected at the native level and the
     * recvConnnectedDatagramImpl does not update the packet with address from
     * which the packet was received
     * 
     * @param packet
     *            the packet to be updated
     */
    private void updatePacketRecvAddress(ServalDatagramPacket packet) {
        packet.setSocketAddress(new ServalSocketAddress(connectedServiceID));
        packet.setAddress(connectedAddress);
    }
    /**
     * Gets the {@code FileDescriptor} of this datagram socket, which
     * is invalid if the socket is closed or not bound.
     * 
     * @return the current file descriptor of this socket.
     */
    protected FileDescriptor getFileDescriptor() {
	    return fd;
    }

    /**
     * Gets the local address to which the socket is bound.
     * 
     * @return the local address to which the socket is bound.
     */
    InetAddress getLocalAddress() {
        // Not implemented a.t.m.
        return null;
    }

    /**
     * Gets the local serviceID to which the socket is bound.
     * 
     * @return the local serviceID to which the socket is bound.
     */
    ServiceID getLocalServiceID() {
        return localServiceID;
    }

    public ServalSocketAddress getLocalSocketAddress() {
        return new ServalSocketAddress(localServiceID, localAddress);
    }
    public Object getSocketOption(int optID) throws SocketException {
        if (fd == null) {
            throw new SocketException("socket not created");
        }

        if (optID == SocketOptions.SO_TIMEOUT) {
            return 0;
        }
        
        int value = netImpl.getOption(fd, optID);

        switch (optID) {
            case SocketOptions.SO_RCVBUF:
            case SocketOptions.SO_SNDBUF:
                return value;
            case SocketOptions.SO_REUSEADDR:
            default:
                return value;
        }
    }

    public void setSocketOption(int optID, Object value)
            throws SocketException {
        /*
         * Boolean.FALSE is used to disable some options, so it
         * is important to distinguish between FALSE and unset.
         * We define it here that -1 is unset, 0 is FALSE, and 1
         * is TRUE.
         */
        int boolValue = -1;
        int intValue = 0;

        if (fd == null) {
            throw new SocketException("socket not created");
        }

        if (value instanceof Integer) {
            intValue = (Integer)value;
        } else if (value instanceof Boolean) {
            boolValue = ((Boolean) value)? 1 : 0;
        } else {
            throw new SocketException("bad value: " + value);
        }

        netImpl.setOption(fd, optID, boolValue, intValue);
    }
}

