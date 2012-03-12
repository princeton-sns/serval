/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.net;

import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.SocketException;

/**
 * A datagram packet supporting SevalSocketAddress based on the
 * DatagramPacket class from Android/Harmony
 */
public final class ServalDatagramPacket {
    byte[] data;

    /**
     * Length of the data to be sent or size of data that was received via
     * DatagramSocket#receive() method call. 
     */
    int length;

    /**
     * Size of internal buffer that is used to store received
     * data. Should be greater or equal to "length" field.
     */
    int capacity;

    ServiceID serviceID;

    InetAddress address = null;

    int offset = 0;

    /**
     * Constructs a new {@code ServalDatagramPacket} object to receive
     * data up to {@code length} bytes.
     * 
     * @param data
     *            a byte array to store the read characters.
     * @param length
     *            the length of the data buffer.
     */
    public ServalDatagramPacket(byte[] data, int length) {
        this(data, 0, length);
    }

    /**
     * Constructs a new {@code ServalDatagramPacket} object to receive
     * data up to {@code length} bytes with a specified buffer offset.
     * 
     * @param data
     *            a byte array to store the read characters.
     * @param offset
     *            the offset of the byte array where the bytes is written.
     * @param length
     *            the length of the data.
     */
    public ServalDatagramPacket(byte[] data, int offset, int length) {
        super();
        setData(data, offset, length);
    }
    /**
     * Constructs a new {@code ServalDatagramPacket} object to send
     * data to a specific instance {@code instance} of the service
     * with ServiceID {@code service}. The {@code length} must be
     * lesser than or equal to the size of {@code data}. The first
     * {@code length} bytes from the byte array position 
     * {@code offset} are sent.
     *
     * @param data
     *            a byte array which stores the characters to be sent.
     * @param offset
     *            the offset of {@code data} where to read from.
     * @param length
     *            the length of data.
     * @param aServiceID
     *            the address of the target service.
     * @param inetAddr
     *            the address of the target service instance.
     */
    public ServalDatagramPacket(byte[] data, int offset, int length,
                                ServiceID service, InetAddress instance) {
        this(data, offset, length);
        setServiceID(service);
        setAddress(instance);
    }
    /**
     * Constructs a new {@code ServalDatagramPacket} object to send
     * data to the service with ServiceID {@code service}. The
     * {@code length} must be lesser than or equal to the size of
     * {@code data}. The first {@code length} bytes from the byte
     * array position {@code offset} are sent.
     *
     * @param data
     *            a byte array which stores the characters to be sent.
     * @param offset
     *            the offset of {@code data} where to read from.
     * @param length
     *            the length of data.
     * @param service
     *            the ServiceID of the target service.
     */
    public ServalDatagramPacket(byte[] data, int offset, int length,
                                ServiceID service) {
        this(data, offset, length, service, null);
    }

    /**
     * Constructs a new {@code ServalDatagramPacket} object to send
     * data to the service with ServiceID {@code service}. The
     * {@code length} must be lesser than or equal to the size of
     * {@code data}. The first {@code length} bytes are sent.
     *
     * @param data
     *            a byte array which stores the characters to be sent.
     * @param length
     *            the length of data.
     * @param service
     *            the ServiceID of the target service.
     */
    public ServalDatagramPacket(byte[] data, int length, 
                                ServiceID service) {
        this(data, 0, length, service);
    }

    /**
     * Constructs a new {@code ServalDatagramPacket} object to send
     * data to the instance {@code instance} of the service with
     * ServiceID {@code service}. The {@code length} must be lesser
     * than or equal to the size of {@code data}. The first 
     * {@code length} bytes are sent.
     *
     * @param data
     *            a byte array which stores the characters to be sent.
     * @param length
     *            the length of data.
     * @param aServiceID
     *            the ServiceID of the target service.
     */
    public ServalDatagramPacket(byte[] data, int length, 
                                ServiceID service, 
                                InetAddress instance) {
        this(data, 0, length, service, instance);
    }

    /**
     * Constructs a new {@code ServalDatagramPacket} object to send
     * data to the address {@code sockAddr}. The {@code length} must
     * be lesser than or equal to the size of {@code data}. The first
     * {@code length} bytes of the data are sent.
     * 
     * @param data
     *            the byte array to store the data.
     * @param length
     *            the length of the data.
     * @param sockAddr
     *            the target host address and port.
     * @throws SocketException
     *             if an error in the underlying protocol occurs.
     */
    public ServalDatagramPacket(byte[] data, int length, SocketAddress sockAddr)
        throws SocketException {
        this(data, 0, length);
        setSocketAddress(sockAddr);
    }

    /**
     * Constructs a new {@code ServalDatagramPacket} object to send
     * data to the address {@code sockAddr}. The {@code length} must
     * be lesser than or equal to the size of {@code data}. The first
     * {@code length} bytes of the data are sent.
     * 
     * @param data
     *            the byte array to store the data.
     * @param offset
     *            the offset of the data.
     * @param length
     *            the length of the data.
     * @param sockAddr
     *            the target host address and port.
     * @throws SocketException
     *             if an error in the underlying protocol occurs.
     */
    public ServalDatagramPacket(byte[] data, int offset, int length,
                                SocketAddress sockAddr) throws SocketException {
        this(data, offset, length);
        setSocketAddress(sockAddr);
    }

    /**
     * Gets the sender or destination IP address of this datagram packet.
     * 
     * @return the address from where the datagram was received or to which it
     *         is sent.
     */
    public synchronized InetAddress getAddress() {
        return address;
    }

    /**
     * Gets the data of this datagram packet.
     * 
     * @return the received data or the data to be sent.
     */
    public synchronized byte[] getData() {
        return data;
    }

    /**
     * Gets the length of the data stored in this datagram packet.
     * 
     * @return the length of the received data or the data to be sent.
     */
    public synchronized int getLength() {
        return length;
    }

    /**
     * Gets the offset of the data stored in this datagram packet.
     * 
     * @return the position of the received data or the data to be sent.
     */
    public synchronized int getOffset() {
        return offset;
    }
    
    /**
     * Sets the {@code ServiceID} for this datagram packet.
     * 
     * @param aServiceID
     *            the serviceID of the target service.
     */
    public synchronized void setServiceID(ServiceID aServiceID) {
        serviceID = aServiceID;
    }
    
    /**
     * Gets the serviceID to which this datagram packet is sent as a
     * {@code ServiceID} object.
     *
     * @return the ServiceID of the target service.
     */
    public synchronized ServiceID getServiceID() {
        return serviceID;
    }


    /**
     * Sets the IP address of the target host.
     * 
     * @param addr
     *            the target host address.
     */
    public synchronized void setAddress(InetAddress addr) {
        address = addr;
    }

    /**
     * Sets the data buffer for this datagram packet.
     * 
     * @param buf
     *            the buffer to store the data.
     * @param anOffset
     *            the buffer offset where the data is stored.
     * @param aLength
     *            the length of the data to be sent or the length of buffer to
     *            store the received data.
     */
    public synchronized void setData(byte[] buf, int anOffset, int aLength) {
        if (0 > anOffset || anOffset > buf.length || 0 > aLength
                || aLength > buf.length - anOffset) {
            throw new IllegalArgumentException("Bad length or offset");
        }
        data = buf;
        offset = anOffset;
        length = aLength;
        capacity = aLength;
    }

    /**
     * Sets the data buffer for this datagram packet. The length of the datagram
     * packet is set to the buffer length.
     * 
     * @param buf
     *            the buffer to store the data.
     */
    public synchronized void setData(byte[] buf) {
        length = buf.length; // This will check for null
        capacity = buf.length;
        data = buf;
        offset = 0;
    }

    /**
     * Gets the current capacity value.
     * 
     * @return the current capacity value
     */
    synchronized int getCapacity() {
        return capacity;
    }

    /**
     * Sets the length of the datagram packet. This length plus the
     * offset must be lesser than or equal to the buffer size.
     * 
     * @param len
     *            the length of this datagram packet.
     */
    public synchronized void setLength(int len) {
        if (0 > len || offset + len > data.length) {
            throw new IllegalArgumentException("Bad offset or length");
        }
        length = len;
        capacity = len;
    }

    /**
     * An alternative to {@link #setLength(int)}, that doesn't reset
     * the {@link #capacity} field.
     * 
     * @param len the length of this datagram packet
     */
    synchronized void setLengthOnly(int len) {
        if (0 > len || offset + len > data.length) {
            throw new IllegalArgumentException("Bad offset or length");
        }
        length = len;
    }

    /**
     * Gets the serviceID and optional address to which this datagram
     * packet is sent as a {@code SocketAddress} object.
     *
     * @return the SocketAddress of the target service.
     */
    public synchronized SocketAddress getSocketAddress() {
        return new ServalSocketAddress(getServiceID(), getAddress());
    }

    /**
     * Sets the {@code SocketAddress} for this datagram packet.
     * 
     * @param sockAddr
     *            the SocketAddress of the target service.
     */
    public synchronized void setSocketAddress(SocketAddress sockAddr) {
        if (!(sockAddr instanceof ServalSocketAddress)) {
            throw new IllegalArgumentException("Not a ServalSocketAddress");
        }
        ServalSocketAddress servalAddr = (ServalSocketAddress) sockAddr;
        serviceID = servalAddr.getServiceID();
        address = servalAddr.getAddress();
    }
}
