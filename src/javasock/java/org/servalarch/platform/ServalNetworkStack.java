/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.platform;

import org.servalarch.net.ServalDatagramSocketImpl;
import org.servalarch.net.ServalSocketImpl;
import org.servalarch.net.ServiceID;
import org.servalarch.net.ServalDatagramPacket;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetAddress;
import java.net.SocketException;

public class ServalNetworkStack {
	private static ServalNetworkStack stack = null;

	private native void nativeInit();

	public native int createDatagramSocket(FileDescriptor fd, int protocol)
			throws SocketException;

	public native int createStreamSocket(FileDescriptor fd, int protocol)
			throws SocketException;

	public native int bind(FileDescriptor fd, ServiceID serviceID, int bindBits)
			throws SocketException;

	public native int listen(FileDescriptor fd, int backlog);

	public native FileDescriptor accept(FileDescriptor fd,
			ServalDatagramSocketImpl sImpl, int timeout)
					throws InterruptedIOException;

	public native FileDescriptor accept(FileDescriptor fd,
			ServalSocketImpl sImpl, int timeout) 
					throws InterruptedIOException;

	public native int connect(FileDescriptor fd, ServiceID serviceID,
			InetAddress address, int timeout) throws SocketException;

	public native int disconnect(FileDescriptor fd) throws SocketException;

	/*
	 * private native int sendto(FileDescriptor fd, byte[] data, int flags);
	 * private native int recvfrom(FileDescriptor fd, byte[] data, int flags);
	 */
	public native int write(FileDescriptor fd, byte[] data, int offset,
			int length) throws InterruptedIOException;

	public native int read(FileDescriptor fd, byte[] data, int offset,
			int length, int timeout) throws InterruptedIOException;

	private native int send(FileDescriptor fd, byte[] data, int offset,
			int length) throws InterruptedIOException;

	private native int recv(FileDescriptor fd, byte[] data, int offset,
			int length, int timeout, boolean peek)
			throws InterruptedIOException;

	public native int close(FileDescriptor fd) throws IOException;

	public native ServiceID getSocketLocalServiceID(FileDescriptor fd);

	public native InetAddress getSocketLocalAddress(FileDescriptor fd);

	public native int setOption(FileDescriptor fd, int optID, int boolValue,
			int intValue);

	public int setOption(FileDescriptor fd, int optID, Object val)
			throws SocketException {
		int boolVal = 0;
		int intVal = 0;

		if (val instanceof Boolean) {
			boolVal = ((Boolean) val) == true ? 1 : 0;
		} else if (val instanceof Integer) {
			intVal = ((Integer) val).intValue();
		} else {
			throw new SocketException("Bad value");
		}
		return setOption(fd, optID, boolVal, intVal);
	}

	public native int getOption(FileDescriptor fd, int optID);

	public native int getSocketFlags();

	public native int availableStream(FileDescriptor fd);

	public native ServiceID getServiceByName(String service);

	public native void shutdownInput(FileDescriptor fd) throws SocketException;

	public native void shutdownOutput(FileDescriptor fd) throws SocketException;

	public native boolean supportsUrgentData(FileDescriptor fd);

	public native void sendUrgentData(FileDescriptor fd, byte val);

	private ServalNetworkStack() {
		nativeInit();
	}

	static public ServalNetworkStack getInstance() {
		return stack == null ? new ServalNetworkStack() : stack;
	}

	public int recvConnectedDatagram(FileDescriptor fd,
			ServalDatagramPacket pack, byte[] data, int offset, int length,
			int timeout, boolean peek) throws InterruptedIOException {
		int len = recv(fd, data, offset, length, timeout, peek);

		if (len > 0) {
			pack.setLength(len);
		} else {
			pack.setLength(0);
		}
		return len;
	}

	public void sendConnectedDatagram(FileDescriptor fd, byte[] data,
			int offset, int length, boolean bindToDevice)
			throws InterruptedIOException {
		send(fd, data, offset, length);
	}

	static {
		System.loadLibrary("servalnet_jni");
	}
}
