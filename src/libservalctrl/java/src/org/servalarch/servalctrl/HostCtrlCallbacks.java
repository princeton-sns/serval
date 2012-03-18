package org.servalarch.servalctrl;

import java.net.InetAddress;

import org.servalarch.net.ServiceID;

/**
 * HostCtrlCallbacks is an abstract class that can be extended or 
 * overridden to implement callback handlers for Serval events.
 * 
 * @author Erik Nordström <enordstr@cs.princeton.edu>
 *
 */
public abstract class HostCtrlCallbacks {
	public static final int RETVAL_OK = 0;
	public static final int RETVAL_ERROR = 1;
	public static final int RETVAL_NOENTRY = 2;
	public static final int RETVAL_MALFORMED = 3;

	/**
	 * Translate an callback return value into a descriptive string.
	 * 
	 * @param  retval the return value to translate.
	 * @return the String describing the return value. 
	 */
	public static String getRetvalString(int retval) {
		switch (retval) {
		case RETVAL_OK:
			return "OK";
		case RETVAL_ERROR:
			return "ERROR";
		case RETVAL_NOENTRY:
			return "NOENTRY";
		case RETVAL_MALFORMED:
			return "MALFORMED";
		default:
		}
		return "UNKNOWN";
	}
	
	/**
	 * This callback is called on a registration event.
	 * 
	 * @param id           	the ServiceID being registered
	 * @param flags        	flags detailing how this registration should be handled
	 * @param prefixBits   	the number of bits of the ServiceID to register. 0 means the entire serviceID.
	 * @param addr         	the address to associate with the ServiceID
	 * @param oldAddr      	the previous address used associated with this registration, 
	 * 						in case this is a re-registration. May be null.
	 */
	public void onServiceRegistration(ServiceID id, int flags, int prefixBits,
			InetAddress addr, InetAddress oldAddr) {
	}
	
	/**
	 *  This callback is called on an unregistration event.
	 *  
	 * @param id			the ServiceID being unregistered
	 * @param flags       	flags detailing how this unregistration should be handled
	 * @param prefixBits	the number of bits of the ServiceID to unregister. 0 means the entire serviceID.
	 * @param addr			the address associated with the ServiceID
	 */
	public void onServiceUnregistration(ServiceID id, int flags, int prefixBits,
			InetAddress addr) {	
	}
	
	/**
	 * Called as a result of a previous service addition request. 
	 * 
	 * @param xid		The transaction ID of this event refers to.
	 * @param retval	Return value indicating the result of the call 
	 * 					that generated this event.
	 * @param info		The service information this events concerns.
	 */
	public void onServiceAdd(long xid, int retval, ServiceInfo[] info) {
				
	}
	
	/**
	 * Called as a result of a previous service removal request. 
	 * 
	 * @param xid		The transaction ID of this event refers to.
	 * @param retval	Return value indicating the result of the call 
	 * 					that generated this event.
	 * @param info		The service information this events concerns.
	 */
	public void onServiceRemove(long xid, int retval, ServiceInfoStat[] info) {
		
	}
	
	/**
	 * Called as a result of a previous service modification request. 
	 * 
	 * @param xid		The transaction ID of this event refers to.
	 * @param retval	Return value indicating the result of the call 
	 * 					that generated this event.
	 * @param info		The service information statistics this events concerns.
	 */
	public void onServiceModify(long xid, int retval, ServiceInfoStat[] info) {
		
	}
	
	/**
	 * Called as a result of a previous service retrieval request. 
	 * 
	 * @param xid		The transaction ID of this event refers to.
	 * @param retval	Return value indicating the result of the call 
	 * 					that generated this event.
	 * @param info		The service information statistics this events concerns.
	 */
	public void onServiceGet(long xid, int retval, ServiceInfo[] info) {
		
	}
}
