package org.servalarch.serval;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.servalarch.net.ServiceID;

import android.app.Service;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.IBinder;
import android.util.Log;

public class TableService extends Service  {

	private static final String TAG = "TableService";
	
	@Override
	public IBinder onBind(Intent arg0) {
		return null;
	}
	
	@Override
	public void onCreate() {
		super.onCreate();
	}

	
	@Override
	public void onDestroy() {
		if (thread != null) {
			thread.interrupt();
			thread = null;
		}
		super.onDestroy();
	}
	
	private SharedPreferences prefs;
	private Thread thread;
	
	@Override
	public int onStartCommand(Intent intent, int startFlags, int startId) {
		if (thread == null) {
			if (prefs == null) {
				prefs = getSharedPreferences("serval", 0);
			}
			startThread();
		}
		return START_STICKY;
	}
	
	private void startThread() {
		if (thread == null) {
			thread = new Thread() {
				boolean running = true;
				
				@Override
				public void run() {
					while (running) {
						Map<String, ?> idMap = prefs.getAll();
						String[] existing = getExistingIds();
						
						persist:
						for (String srvID : idMap.keySet()) {
							if (!(idMap.get(srvID) instanceof String))
								continue;
							Log.v(TAG, "Checking " + srvID);
							String res[] = srvID.split(":");
							int prefixBits = 256;
							
							if (res.length == 2)
								prefixBits = Integer.parseInt(res[1]);
							
							ServiceID sid = AppHostCtrl.createServiceID(res[0]);
							for (String s : existing) {
								if (sid.toString().equals(s))
									continue persist;
							}
							String addr = (String) idMap.get(srvID);
							Log.v(TAG, "Adding " + srvID + " | " + addr);
							AppHostCtrl.performOp(TableService.this, srvID, addr, AppHostCtrl.SERVICE_ADD);
						}
						try {
							Thread.sleep(3000);
						} catch (InterruptedException e) {
						}
					}
				}
				
				private String[] getExistingIds() {
					File table = new File("/proc/net/serval/service_table");
					String[] ret = new String[0];
					if (!table.exists())
						return ret;
					else {
						try {
							List<String> ids = new Vector<String>();
							BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(table)));

							String line = in.readLine();
							while ((line = in.readLine()) != null) {
								String[] args = line.split("\\s+");
								ids.add(args[0]);
							}
							in.close();
							ret = new String[ids.size()];
							for (int i = 0; i < ret.length; i++)
								ret[i] = ids.get(i);
						} catch (Exception e) {
							return ret;
						}
						return ret;
					}
				}
				
				@Override
				public void interrupt() {
					running = false;
					super.interrupt();
				}
			};
			thread.start();
		}
	}
}
