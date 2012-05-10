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
        	ConnectivityManager connManager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
    		
        	NetworkInfo info = (NetworkInfo) intent.getParcelableExtra(ConnectivityManager.EXTRA_NETWORK_INFO);
    		int opp = (info.getType() == ConnectivityManager.TYPE_WIFI) ? ConnectivityManager.TYPE_MOBILE :
    			ConnectivityManager.TYPE_WIFI;
    		NetworkInfo other = connManager.getNetworkInfo(opp);
    		Map<String, ?> idMap = prefs.getAll();
    		
    		/* Connected, add rules back */
        	if (info.getState().equals(NetworkInfo.State.CONNECTED)) {
        		performAction(context, idMap, AppHostCtrl.SERVICE_REMOVE);
    			performAction(context, idMap, AppHostCtrl.SERVICE_ADD);
        	}
        	/* Disconnected, remove rules */
        	else if (info.getState().equals(NetworkInfo.State.DISCONNECTED)) {
    			performAction(context, idMap, AppHostCtrl.SERVICE_REMOVE);
    			
    			/* Make rules available, since other interface is up */
        		if (other.isConnectedOrConnecting()) {
        			performAction(context, idMap, AppHostCtrl.SERVICE_ADD);
        		}
        	}
        }
    }
	
	private void performAction(Context context, Map<String, ?> idMap, int action) {
		for (String srvID : idMap.keySet()) {
			if (!(idMap.get(srvID) instanceof String))
				continue;
			String addr = (String) idMap.get(srvID);
			AppHostCtrl.performOp(context.getApplicationContext(), srvID, addr, action);
		}
	}
}
