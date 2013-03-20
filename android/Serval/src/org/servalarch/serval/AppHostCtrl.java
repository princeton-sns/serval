/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
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

	static void performOp(Context context, final String serviceStr,
			final String ipStr, int op) {
		ServiceID sid;
		InetAddress addr = null;
		int type = HostCtrl.SERVICE_RULE_FORWARD;

		if (hc == null)
			return;
		
		sid = AppHostCtrl.createServiceID(serviceStr);

		if (sid == null) {
			Toast t = Toast.makeText(context, "Not a valid serviceID",
					Toast.LENGTH_SHORT);
			t.show();
			return;
		}

		if (ipStr == "delay") {
			type = HostCtrl.SERVICE_RULE_DELAY;
		} else if (ipStr == "drop") {
			type = HostCtrl.SERVICE_RULE_DROP;
		} else {
			addr = AppHostCtrl.createAddress(ipStr);

			if (addr == null) {
				Toast t = Toast.makeText(context, "Not a valid IP address",
						Toast.LENGTH_SHORT);
				t.show();
				return;
			}
		}

		switch (op) {
		case AppHostCtrl.SERVICE_ADD:
			Log.d("Serval", "adding service " + sid + " type " + type + " address " + addr);
			AppHostCtrl.hc.addService(type, sid, 1, 1, addr);
			break;
		case AppHostCtrl.SERVICE_REMOVE:
			AppHostCtrl.hc.removeService(sid, addr);
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
        try {
            sid = new ServiceID(serviceStr);
        } catch (IllegalArgumentException e) {
        }
        return sid;
    }
}
