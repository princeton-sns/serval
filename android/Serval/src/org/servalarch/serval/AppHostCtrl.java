package org.servalarch.serval;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.servalarch.net.ServiceID;
import org.servalarch.servalctrl.HostCtrl;

public class AppHostCtrl {

	static final int SERVICE_ADD = 0;
	static final int SERVICE_REMOVE = 1;
	
	static HostCtrl hc = null;
	
	static InetAddress createAddress(String ipStr) {
		InetAddress addr = null;
		try {
			addr = InetAddress.getByName(ipStr);
		} catch (UnknownHostException e) {
			
		}
		return addr;
	}

	static ServiceID createServiceID(String serviceStr) {
		ServiceID sid = null;
		
		if (serviceStr.length() > 2 && serviceStr.charAt(0) == '0' && serviceStr.charAt(1) == 'x') {
			// Hex string
			if (!serviceStr.matches("^0x[a-fA-F0-9]{1,40}$"))
				return null;
			
			String parseStr = serviceStr.substring(2);
			int len = parseStr.length();
			
			byte[] rawID = new byte[ServiceID.SERVICE_ID_MAX_LENGTH];
			
			for (int i = 0; i < rawID.length; i++) {
				char hex[] = { '0', '0' };
		
				if (len-- > 0) {
					hex[0] = parseStr.charAt(i*2);
				}
				
				if (len-- > 0) {
					hex[1] = parseStr.charAt((i*2) + 1);
				}
				
				rawID[i] = (byte)Integer.parseInt(new String(hex), 16);
				
				if (len <= 0)
					break;
			}
			
			sid = new ServiceID(rawID);
		} else {
			// Decimal string
			if (!serviceStr.matches("^[0-9]{1,20}$"))
				return null;
			sid = new ServiceID(Integer.parseInt(serviceStr));
		}
		return sid;
	}
}
