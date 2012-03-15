package org.servalarch.servalctrl;

import java.net.InetAddress;
import java.net.UnknownHostException;

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
				public void onServiceRegistration(ServiceID id, int flags,
						int prefixBits, InetAddress addr, InetAddress oldAddr) {
					System.out.println("REGISTER: serviceID " + id.toString() + " addr " + addr.toString());
				}

				@Override
				public void onServiceUnregistration(ServiceID id, int flags,
						int prefixBits, InetAddress addr) {
					System.out.println("UNREGISTER: serviceID " + id.toString() + " addr " + addr.toString());
				}

				@Override
				public void onServiceGet(long xid, int retval, ServiceInfo[] info) {
					for (int i = 0; i < info.length; i++) {
						System.out.println("GET " +
								getRetvalString(retval) + 
								": serviceID " + info[i].getServiceID() + 
								" addr " + info[i].getAddress() + 
								" priority " + info[i].getPriority() + 
								" weight " + info[i].getWeight());
					}
				}
				@Override
				public void onServiceAdd(long xid, int retval, ServiceInfo[] info) {
						for (int i = 0; i < info.length; i++) {
							System.out.println("ADDED " + 
									getRetvalString(retval) + ": serviceID " + 
									info[i].getServiceID() + 
									" addr " + info[i].getAddress() + 
									" priority " + info[i].getPriority() + 
									" weight " + info[i].getWeight());
						}
				}
				@Override
				public void onServiceRemove(long xid, int retval, ServiceInfoStat[] info) {
					for (int i = 0; i < info.length; i++) {
						System.out.println("REMOVED " + 
								getRetvalString(retval) + ": serviceID " + 
								info[i].getServiceID() + 
								" addr " + info[i].getAddress() + 
								" priority " + info[i].getPriority() + 
								" weight " + info[i].getWeight());
					}
				}
			});
		} catch (HostCtrlException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		}
		
		
		try {
			InetAddress addr = InetAddress.getByName("192.168.6.45");

			hc.addService(new ServiceID(808), addr);
			
			Thread.sleep(1000);
			
			hc.getService(new ServiceID(0), 0, null);
			
			System.out.println("Waiting 3 seconds for events...");
			
			Thread.sleep(3000);
			
			hc.removeService(new ServiceID(808), addr);

			System.out.println("Waiting 3 seconds before exiting...");
			
			Thread.sleep(3000);
		} catch (UnknownHostException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("Done... exiting");
		
		hc.dispose();
	}
}
