package org.servalarch.serval;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.servalarch.servalctrl.HostCtrlCallbacks;
import org.servalarch.servalctrl.ServiceInfo;
import org.servalarch.servalctrl.ServiceInfoStat;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentActivity;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentPagerAdapter;
import android.support.v4.view.ViewPager;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.Toast;
import android.widget.ToggleButton;


public class ServalActivity extends FragmentActivity {

	private static final int DEFAULT_IDX = 2;

	private Button moduleStatusButton;
	private Button udpEncapButton;
	private File module = null;
	
	private SharedPreferences prefs;
	private PagerAdapter pagerAdapter;

	private ServalFragment servalFrag;
	
	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		prefs = getSharedPreferences("serval", 0);
		setContentView(R.layout.main);
		List<Fragment> fragments = new Vector<Fragment>();
		fragments.add(Fragment.instantiate(this, FlowTableFragment.class.getName()));
		fragments.add(Fragment.instantiate(this, ServiceTableFragment.class.getName()));
		servalFrag = (ServalFragment) Fragment.instantiate(this, ServalFragment.class.getName());
		fragments.add(servalFrag);
		fragments.add(Fragment.instantiate(this, TranslatorFragment.class.getName()));
		this.pagerAdapter = new PagerAdapter(super.getSupportFragmentManager(), fragments);
		ViewPager pager = (ViewPager) super.findViewById(R.id.pager);
		pager.setAdapter(this.pagerAdapter);
		pager.setCurrentItem(DEFAULT_IDX);

		File filesDir = getExternalFilesDir(null);
		try {
			filesDir.createNewFile();
		} catch (IOException e) {
			e.printStackTrace();
		}
		module = new File(filesDir, "serval.ko");
		
		this.moduleStatusButton = (Button) findViewById(R.id.moduleStatusToggle);
		this.moduleStatusButton.setOnClickListener(new OnClickListener() {
			
			@Override
			public void onClick(View v) {
				boolean isLoaded = isServalModuleLoaded();
				boolean addPersistent = !isLoaded;
				String cmd;

				if (!moduleStatusButton.isSelected()) {
					if (isLoaded) {
						setModuleLoaded(isLoaded);
						return;
					}

					cmd = "insmod " + module.getAbsolutePath();
					
				} 
				else {
					if (!isLoaded) {
						setModuleLoaded(isLoaded);
						return;
					}
					cmd = "rmmod serval";
					

					AppHostCtrl.fini();					
				}

				if (!executeSuCommand(cmd)) {
					Toast t = Toast.makeText(getApplicationContext(), cmd + " failed!", 
							Toast.LENGTH_SHORT);
					t.show();
				}

				if (!isServalModuleLoaded()) {
					setModuleLoaded(false);
					setUdpEncap(false);
				} 
				else {
					setModuleLoaded(true);
					
					AppHostCtrl.init(cbs);
					/* insert persistent rules */
					if (addPersistent) {
						Map<String, ?> idMap = prefs.getAll();
		        		for (String srvID : idMap.keySet()) {
		        			if (!(idMap.get(srvID) instanceof String))
		        				continue;
		        			String addr = (String) idMap.get(srvID);
		        			AppHostCtrl.performOp(getApplicationContext(), srvID, addr, AppHostCtrl.SERVICE_ADD);
		        		}
					}
				}
			}

		});
		
		this.udpEncapButton = (Button) findViewById(R.id.udpEncapToggle);
		this.udpEncapButton.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View v) {
				String cmd;
				
				if (!isServalModuleLoaded()) {
					setUdpEncap(false);
					return;
				}
				
				if (!udpEncapButton.isSelected())
					 cmd = "echo 1 > /proc/sys/net/serval/udp_encap";
				else
					 cmd = "echo 0 > /proc/sys/net/serval/udp_encap";

				if (!executeSuCommand(cmd)) {
					Toast t = Toast.makeText(getApplicationContext(), cmd + " failed!", 
							Toast.LENGTH_SHORT);
					t.show();
				}
				setUdpEncap(isUdpEncapEnabled());
			}
		});
		
	}
		
	private boolean extractKernelModule(final File module) {
		if (module.exists())
			return true;

		try {
			BufferedInputStream in = new BufferedInputStream(getAssets().open("serval.ko"));

			byte[] buffer = new byte[1024];
			int n, tot = 0;

			FileOutputStream os = new FileOutputStream(module);
			BufferedOutputStream out = new BufferedOutputStream(os);

			while ((n = in.read(buffer, 0, 1024)) != -1) {
				out.write(buffer, 0, n);
				tot += n;
			}
			out.close();
			in.close();
			
			Log.d("Serval", "Wrote " + tot + " bytes to " + module.getAbsolutePath());
			return true;
		} catch (IOException e) {
			e.printStackTrace();
		}

		return false;
	}

	boolean executeSuCommand(final String cmd) {
		try {
			Process shell;
			int err;

			shell = Runtime.getRuntime().exec("su");
			DataOutputStream os = new DataOutputStream(shell.getOutputStream());
			os.writeBytes(cmd + "\n");
			os.flush();
			os.writeBytes("exit\n");
			os.flush();
			os.close();

			err = shell.waitFor();

			if (err == 0)
				return true;

		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		Log.d("Serval", cmd + " failed!");

		return false;
	}
	
	private boolean isUdpEncapEnabled() {
		boolean encapIsEnabled = false;
		File encap = new File("/proc/sys/net/serval/udp_encap");

		if (encap.exists() && encap.canRead()) {
			try {
				BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(encap)));

				String line = in.readLine();

				if (line.contains("1"))
					encapIsEnabled = true;
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		} else {
			Log.d("Serval", "could not open /proc/sys/net/serval/udp_encap");
		}
		return encapIsEnabled;
	}
	
	private boolean isServalModuleLoaded() {
		File procModules = new File("/proc/modules");

		if (procModules.exists() && procModules.canRead()) {
			try {
				BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(procModules)));

				String line = null; 
				while ((line = in.readLine()) != null) {
					if (line.contains("serval")) {
						return true;
					}
				}
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		} else {
			Log.d("Serval", "could not open /proc/modules");
		}
		return false;
	}
	
	public void setModuleLoaded(boolean loaded) {
		String text = getString(loaded ? R.string.module_loaded : 
										 R.string.module_unloaded);
		moduleStatusButton.setSelected(loaded);
		moduleStatusButton.setText(text);
	}
	
	public void setUdpEncap(boolean on) {
		String text = getString(on ? R.string.udp_on : R.string.udp_off);
		udpEncapButton.setSelected(on);
		udpEncapButton.setText(text);
	}

	@Override
	public void onBackPressed() {
		super.onBackPressed();
	}

	private final HostCtrlCallbacks cbs = new HostCtrlCallbacks() {
		@Override
		public void onServiceAdd(long xid, final int retval, ServiceInfo[] info) {
			runOnUiThread(new Runnable() {
				@Override
				public void run() {
					String msg;
					if (retval == RETVAL_OK) {
						msg = "Added service";
						if (servalFrag.servicePerm.isChecked()) {
							Log.d("Serval", "Saving rule...");
							prefs.edit().putString(servalFrag.editServiceText.getText().toString(), 
									servalFrag.editIpText.getText().toString()).commit();
						}
					}
					else
						msg = "Add service failed retval=" + retval + " " + getRetvalString(retval);
					
					Toast t = Toast.makeText(getApplicationContext(), msg, 
							Toast.LENGTH_SHORT);
					t.setGravity(Gravity.CENTER, 0, 0);
					t.show();
				}
			});
		}

		@Override
		public void onServiceRemove(long xid, final int retval, ServiceInfoStat[] info) {
			runOnUiThread(new Runnable() {
				@Override
				public void run() {
					String msg;
					if (retval == RETVAL_OK) { 
						msg = "Removed service";
						prefs.edit().remove(servalFrag.editServiceText.getText().toString()).commit();
					}
					else
						msg = "Remove service failed retval=" + retval + " " + getRetvalString(retval);
					
					Toast t = Toast.makeText(getApplicationContext(), msg, 
							Toast.LENGTH_LONG);
					t.setGravity(Gravity.CENTER, 0, 0);
					t.show();
				}
			});
		}

		@Override
		public void onServiceGet(long xid, final int retval, ServiceInfo[] info) {
			for (int i = 0; i < info.length; i++) {
				Log.d("Serval", "RETRIEVED: Service " + info[i].getServiceID() + 
						"address " + info[i].getAddress());
			}
		}
	};
	
	@Override
	protected void onStart() {
		super.onStart();

		Log.d("Serval", "module path is " + module.getAbsolutePath());

		if (!extractKernelModule(module)) {
			Log.d("Serval", "Could not extract kernel module");
		}

		setModuleLoaded(isServalModuleLoaded());
		setUdpEncap(isUdpEncapEnabled());

		AppHostCtrl.init(cbs);
	}
	
	@Override
	protected void onStop() {
		super.onStop();
		Log.d("Serval", "Stopping Serval host control");
	}
	
	@Override
	protected void onDestroy() {
		super.onDestroy();
		Log.d("Serval", "Destroying Serval host control");
		AppHostCtrl.fini();
	}
	
	private class PagerAdapter extends FragmentPagerAdapter {

		private List<Fragment> fragments;
		private String[] titles;

		public PagerAdapter(FragmentManager fm, List<Fragment> fragments) {
			super(fm);
			this.fragments = fragments;
			this.titles = ServalActivity.this.getResources().getStringArray(R.array.pager_titles);
		}

		@Override
		public Fragment getItem(int position) {
			return this.fragments.get(position);
		}
		
		@Override
		public CharSequence getPageTitle(int position) {
			return titles[position];
		}
		
		@Override
		public int getCount() {
			return this.fragments.size();
		}
	}
}
