package org.servalarch.serval;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.servalarch.net.ServiceID;
import org.servalarch.servalctrl.HostCtrl;
import org.servalarch.servalctrl.HostCtrl.HostCtrlException;
import org.servalarch.servalctrl.HostCtrlCallbacks;
import org.servalarch.servalctrl.LocalHostCtrl;

import android.content.Context;
import android.util.Log;
import android.widget.Toast;

public class AppHostCtrl {

	static final int SERVICE_ADD = 0;
	static final int SERVICE_REMOVE = 1;
	static HostCtrlCallbacks cbs = null;
	static HostCtrl hc = null;
	
	static int init(final HostCtrlCallbacks cbs) {
		
		if (hc != null) {
			Log.d("Serval", "HostCtrl already initialized");
			return 0;
		}
		
		try {
			AppHostCtrl.hc = new LocalHostCtrl(cbs);
		} catch (HostCtrlException e) {
			Log.d("Serval", "Could not initialize HostCtrl");
			return -1;
		}
		AppHostCtrl.cbs = cbs;
		Log.d("Serval", "HostCtrl initialized");
		return 0;
	}
	
	static void fini() {
		if (hc != null) {
			hc.dispose();
			hc = null;
			cbs = null;
		}
	}

	static void performOp(Context context, final String serviceStr, final String ipStr, int op) {
		ServiceID sid;
		InetAddress addr;
		
		if (hc == null)
			return;

		sid = AppHostCtrl.createServiceID(serviceStr);
		
		if (sid == null) {
			Toast t = Toast.makeText(context, "Not a valid serviceID", 
					Toast.LENGTH_SHORT);
			t.show();
			return;
		}
		
		addr = AppHostCtrl.createAddress(ipStr);
		
		if (addr == null) {
			Toast t = Toast.makeText(context, "Not a valid IP address", 
					Toast.LENGTH_SHORT);
			t.show();
			return;
		}
		
		switch (op) {
		case AppHostCtrl.SERVICE_ADD:
			Log.d("Serval", "adding service " + sid + " address " + addr);
			AppHostCtrl.hc.addService(sid, 0, 1, 1, addr);
			break;
		case AppHostCtrl.SERVICE_REMOVE:
			AppHostCtrl.hc.removeService(sid, 0, addr);
			break;
		default:
			break;
		}
	}
	
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
