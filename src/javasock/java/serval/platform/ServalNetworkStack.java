/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package serval.platform;

import serval.net.ServalDatagramSocketImpl;
import serval.net.ServiceID;
import serval.net.ServalSocketAddress;
import serval.net.ServalDatagramPacket;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketOptions;
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
				 ServalDatagramSocketImpl sImpl);
	public native int connect(FileDescriptor fd, ServiceID serviceID, 
                              InetAddress address) throws SocketException;
    public native int disconnect(FileDescriptor fd) throws SocketException;
	/*
	  private native int sendto(FileDescriptor fd, byte[] data, int flags);
	  private native int recvfrom(FileDescriptor fd, byte[] data, int flags);
	*/
	private native int send(FileDescriptor fd, byte[] data, 
                            int offset, int length) 
        throws InterruptedIOException;
	private native int recv(FileDescriptor fd, byte[] data, int offset, 
                            int length, int timeout, boolean peek) 
        throws InterruptedIOException;
    public native int close(FileDescriptor fd) throws IOException;
	public native ServiceID getSocketLocalServiceID(FileDescriptor fd);
	public native int setOption(FileDescriptor fd, int optID, 
                                int boolValue, int intValue);
	public native int getOption(FileDescriptor fd, int optID);
    public native int getSocketFlags();
	
	private ServalNetworkStack() {
        nativeInit();
	}

	static public ServalNetworkStack getInstance() {
		return stack == null ? new ServalNetworkStack() : stack;
	}
    
	public void recvConnectedDatagram(FileDescriptor fd, 
                                      ServalDatagramPacket pack,
                                      byte[] data, int offset, int length, 
                                      int timeout, boolean peek)
        throws InterruptedIOException {
        int len = recv(fd, data, offset, length, timeout, peek);
        
        if (len > 0) {
            pack.setLength(len);
        }
	}
    
	public void sendConnectedDatagram(FileDescriptor fd, byte[] data, 
                                      int offset, int length, 
                                      boolean bindToDevice) 
        throws InterruptedIOException {
        send(fd, data, offset, length);
	}

	static {
		System.loadLibrary("servalnet_jni");
	}
}
