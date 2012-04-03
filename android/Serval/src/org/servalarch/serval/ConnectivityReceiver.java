package org.servalarch.serval;

import java.net.InetAddress;
import java.util.Map;

import org.servalarch.net.ServiceID;
import org.servalarch.servalctrl.HostCtrl;
import org.servalarch.servalctrl.HostCtrlCallbacks;
import org.servalarch.servalctrl.HostCtrl.HostCtrlException;
import org.servalarch.servalctrl.LocalHostCtrl;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.util.Log;
import android.widget.Toast;

public class ConnectivityReceiver extends BroadcastReceiver {

	private HostCtrl hc;
	private SharedPreferences prefs;
	
	private final HostCtrlCallbacks cbs = new HostCtrlCallbacks() {
		
	};
	
	@Override
    public void onReceive(Context context, Intent intent) {
		if (prefs == null) {
			prefs = context.getSharedPreferences("serval", 0);
		}
		if (AppHostCtrl.hc == null) {
			try {
				Log.d("br", "Trying to create hc...");
				AppHostCtrl.hc = new LocalHostCtrl(cbs);
			} catch (HostCtrlException e) {
				e.printStackTrace();
			}
		}
        if (intent.getAction().equals(ConnectivityManager.CONNECTIVITY_ACTION)) {
        	NetworkInfo info = (NetworkInfo) intent.getParcelableExtra(ConnectivityManager.EXTRA_NETWORK_INFO);
        	if (info.getState().equals(NetworkInfo.State.CONNECTED)) {
        		Map<String, ?> idMap = prefs.getAll();
        		for (String srvID : idMap.keySet()) {
        			if (!(idMap.get(srvID) instanceof String))
        				continue;
        			String addr = (String) idMap.get(srvID);
        			performOp(context.getApplicationContext(), srvID, addr, AppHostCtrl.SERVICE_ADD);
        		}
        	}
        }
    }

	private void performOp(Context context, final String serviceStr, final String ipStr, int op) {
		ServiceID sid;
		InetAddress addr;
		
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
}
