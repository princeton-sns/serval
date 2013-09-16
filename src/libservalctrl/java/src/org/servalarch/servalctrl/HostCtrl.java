/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.servalctrl;

import java.net.Inet4Address;
import java.net.InetAddress;
import org.servalarch.net.ServiceID;

public abstract class HostCtrl {
	private long nativeHandle = 0;
	private final HostCtrlCallbacks callbacks;
	private int type;
	private boolean isDisposed = false;
	protected static final int HOSTCTRL_LOCAL = 0;
	protected static final int HOSTCTRL_REMOTE = 1;

	public static final int SERVICE_RULE_UNDEFINED = 0;
	public static final int SERVICE_RULE_FORWARD = 1;
	public static final int SERVICE_RULE_DEMUX = 2;
	public static final int SERVICE_RULE_DELAY = 3;
	public static final int SERVICE_RULE_DROP = 4;
	
	public static final int DELAY_VERDICT_RELEASE = 0;
	public static final int DELAY_VERDICT_DROP = 1;

	public HostCtrl(int type, final HostCtrlCallbacks cb)
			throws HostCtrlException {
		switch (type) {
		case HOSTCTRL_LOCAL:
		case HOSTCTRL_REMOTE:
			int ret = nativeInit(type);

			if (ret == -1)
				throw new HostCtrlException("Initialization failure ret=" + ret);
			break;
		default:
			throw new IllegalArgumentException("No such host control type "
					+ type);
		}
		this.type = type;
		this.callbacks = cb;
	}

	private native int nativeInit(int type);

	private native void nativeFree();

	public native int migrateFlow(long flowID, String toDevice);

	public native int migrateInterface(String fromDevice, String toDevice);
	public native int statsFlow(long[] flowIDs, int flows);

	private native int addService4(int type, ServiceID id, int prefixBits,
			int prority, int weight, Inet4Address addr);

	private native int getService4(ServiceID id, int prefixBits,
			Inet4Address addr);

	private native int removeService4(ServiceID id, int prefixBits,
			Inet4Address addr);

	private native int registerService4(ServiceID id, int prefixBits,
			Inet4Address oldAddr);

	private native int unregisterService4(ServiceID id, int prefixBits);

	public native int setDelayVerdict(long pktId, int verdict);
	
	/**
	 * Returns the transaction ID of the last sent request.
	 */
	private native long getXid();

	public int addService(ServiceID id, int prefixBits, int priority,
			int weight, InetAddress addr) {
		if (!(addr instanceof Inet4Address)) {
			return -1;
		}
		if (prefixBits < 0 || prefixBits > 256)
			prefixBits = 0;
		return addService4(SERVICE_RULE_FORWARD, id, prefixBits, priority,
				weight, (Inet4Address) addr);
	}

	public int addService(ServiceID id, InetAddress addr) {
		return addService(id, id.getLength() * 8, 1, 1, addr);
	}

	public int addServiceDelay(ServiceID id, int prefixBits, int priority, int weight) {
		if (prefixBits < 0 || prefixBits > 256)
			prefixBits = 0;
		return addService4(SERVICE_RULE_DELAY, id, prefixBits, priority,
				weight, null);
	}
	
	public int addServiceDrop(ServiceID id, int prefixBits, int priority, int weight) {
		if (prefixBits < 0 || prefixBits > 256)
			prefixBits = 0;
		return addService4(SERVICE_RULE_DROP, id, prefixBits, priority,
				weight, null);
	}
	
	public int addService(final int type, ServiceID id, int prefixBits, 
			int priority, int weight, InetAddress addr) {
		if (prefixBits < 0 || prefixBits > 256)
			prefixBits = 0;
		return addService4(type, id, prefixBits, priority, weight, (Inet4Address) addr);
	}
	
	public int getService(ServiceID id, int prefixBits, InetAddress addr) {
		if (addr != null && !(addr instanceof Inet4Address)) {
			return -1;
		}
		if (prefixBits < 0 || prefixBits > 256)
			prefixBits = 0;
		return getService4(id, prefixBits, (Inet4Address) addr);
	}

	public int getService(ServiceID id, InetAddress addr) {
		return getService(id, id.getLength() * 8, addr);
	}

	public int removeService(ServiceID id, int prefixBits, InetAddress addr) {
		if (!(addr instanceof Inet4Address)) {
			return -1;
		}
		if (prefixBits < 0 || prefixBits > 256)
			prefixBits = 0;
		return removeService4(id, prefixBits, (Inet4Address) addr);
	}

	public int removeService(ServiceID id, InetAddress addr) {
		return removeService(id, 0, addr);
	}

	public synchronized void dispose() {
		if (!isDisposed) {
			isDisposed = true;
			nativeFree();
		}
	}

	protected void finalize() throws Throwable {
		dispose();
		super.finalize();
	}

	static {
		System.loadLibrary("servalctrl");
		System.loadLibrary("servalctrl_jni");
	}

	public class HostCtrlException extends Exception {
		private static final long serialVersionUID = 1037378741410447851L;

		HostCtrlException(String msg) {
			super(msg);
		}
	}
}
