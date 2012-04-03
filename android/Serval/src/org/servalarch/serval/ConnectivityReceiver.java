package org.servalarch.serval;

import java.util.Map;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;

public class ConnectivityReceiver extends BroadcastReceiver {
	private SharedPreferences prefs;

	@Override
    public void onReceive(Context context, Intent intent) {
		if (prefs == null) {
			prefs = context.getSharedPreferences("serval", 0);
		}
		
        if (intent.getAction().equals(ConnectivityManager.CONNECTIVITY_ACTION)) {
        	NetworkInfo info = (NetworkInfo) intent.getParcelableExtra(ConnectivityManager.EXTRA_NETWORK_INFO);
        	if (info.getState().equals(NetworkInfo.State.CONNECTED)) {
        		Map<String, ?> idMap = prefs.getAll();
        		for (String srvID : idMap.keySet()) {
        			if (!(idMap.get(srvID) instanceof String))
        				continue;
        			String addr = (String) idMap.get(srvID);
        			AppHostCtrl.performOp(context.getApplicationContext(), srvID, addr, AppHostCtrl.SERVICE_ADD);
        		}
        	}
        }
    }
}
