package org.servalarch.serval;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.util.Log;

public class ConnectivityReceiver extends BroadcastReceiver {

	@Override
    public void onReceive(Context context, Intent intent) {
		SharedPreferences prefs = context.getSharedPreferences("serval", 0);
        Log.d(ConnectivityReceiver.class.getSimpleName(), "action: "
                + intent.getAction());
    }

}
