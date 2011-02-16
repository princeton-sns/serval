/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package serval.net;

import java.net.Socket;
import java.net.SocketAddress;
import java.net.DatagramPacket;
import java.net.SocketException;
import java.io.IOException;

/*
  This is a very crude initial implementation of Serval sockets for
  Java. A better implementation would mimic the implementation of
  regular java.net.Socket sockets.
 */
public class ServalDatagramSocket {
	int fd = -1;
	boolean isBound = false;
	boolean isConnected = false;
	ServalSocketAddress peerAddr = null;

	private native int socket();
	private native int bind(int fd, byte[] serviceid);
	private native int listen(int fd, int backlog);	
	private native int accept(int fd, byte[] serviceid);
	private native int connect(int fd, byte[] serviceid);
	private native int send(int fd, byte[] data, int flags);
	private native int recv(int fd, byte[] data, int flags);
	private native int close(int fd);
	
	private ServalDatagramSocket(int fd, ServalSocketAddress peer) {
		this.fd = fd;
		this.peerAddr = peer;
	}

	public ServalDatagramSocket() throws SocketException {
		fd = socket();
		
		if (fd == -1) {
			throw new SocketException("socket failed");
		}
	}
	
	public void bind(SocketAddress sa) throws SocketException {
		if (sa != null) {
			if (!(sa instanceof ServalSocketAddress)) {
				throw new IllegalArgumentException();
			}
			ServalSocketAddress ssa = (ServalSocketAddress)sa;

			if (bind(fd, ssa.getServiceId().getId()) == -1) {
				throw new SocketException("bind failed");
			}
			isBound = true;
		}
	}

	public void listen(int backlog) throws SocketException {
		if (listen(fd, backlog) == -1) {
			throw new SocketException();
		}
	}
	
	public ServalDatagramSocket accept() throws SocketException {
		int clientFd = -1;
		byte serviceid[] = new byte[2]; 
		
		clientFd = accept(fd, serviceid);

		if (clientFd == -1) {
			throw new SocketException();
		}
		
		return new ServalDatagramSocket(clientFd, new ServalSocketAddress(new ServiceId(serviceid)));
	}

	public void connect(SocketAddress peer) throws SocketException {
		if (peer != null) {
			if (!(peer instanceof ServalSocketAddress)) {
				throw new IllegalArgumentException();
			}
			
			ServalSocketAddress ssa = (ServalSocketAddress)peer;
			if (connect(fd, ssa.getServiceId().getId()) == -1) {
				throw new SocketException("connect failed");
			}
			isConnected = true;
		}
	}

	public void send(DatagramPacket pack) throws IOException {
		SocketAddress peer = null; //pack.getSocketAddress();
		
		if (peer != null) {
			// sendto
			
		} else {
			if (send(fd, pack.getData(), 0) == -1) {
				throw new IOException("send failed");
			}
		}
	}
	
	public void receive(DatagramPacket pack) throws IOException {
		//ServalSocketAddress peer;

		if (pack == null) {
			throw new NullPointerException();
		}
		if (isConnected) {
			byte[] buffer = new byte[2000];
			int len = recv(fd, buffer, 0);

			if (len == -1) {
				throw new IOException("receive failed");
			}
			pack.setData(buffer, 0, len);
		} else {
			// sendto
		}
	}
	public void close() {
		if (fd != -1) {
			close(fd);
		}
	}
	static {
        System.loadLibrary("serval_javasock_jni");
    }
}
