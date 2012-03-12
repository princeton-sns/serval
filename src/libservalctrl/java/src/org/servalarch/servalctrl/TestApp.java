package org.servalarch.servalctrl;

import java.net.InetAddress;

import org.servalarch.net.ServiceID;
import org.servalarch.servalctrl.HostCtrl.HostCtrlException;

public class TestApp {
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		LocalHostCtrl hc;
		try {
			hc = new LocalHostCtrl(new HostCtrlCallbacks() {

				@Override
				public void serviceRegistration(ServiceID id, int flags,
						int prefixBits, InetAddress addr, InetAddress oldAddr) {
					System.out.println("REGISTER: serviceID " + id.toString() + " addr " + addr.toString());
				}

				@Override
				public void serviceUnregistration(ServiceID id, int flags,
						int prefixBits, InetAddress addr) {
					System.out.println("UNREGISTER: serviceID " + id.toString() + " addr " + addr.toString());
				}

				@Override
				public void serviceGet(ServiceID id, int flags, int prefixBits,
						int priority, int weight, InetAddress addr) {
					System.out.println("GET: serviceID " + id.toString() + " addr " + addr.toString());
				}

			});
		} catch (HostCtrlException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		}
		
		System.out.println("Waiting 10 seconds for events...");
		try {
			Thread.sleep(10000);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.println("Done... exiting");
		
		hc.dispose();
	}
}
