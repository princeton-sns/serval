/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.serval;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.servalarch.net.ServiceID;
import org.servalarch.servalctrl.HostCtrlCallbacks;
import org.servalarch.servalctrl.ServiceInfo;
import org.servalarch.servalctrl.ServiceInfoStat;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentActivity;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentPagerAdapter;
import android.support.v4.view.ViewPager;
import android.text.Html;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.Toast;

public class ServalActivity extends FragmentActivity {

	private static final int DEFAULT_IDX = 2;

	private Button moduleStatusButton;
	private Button udpEncapButton;
	private SharedPreferences prefs;
	private PagerAdapter pagerAdapter;

	private ServalFragment servalFrag;
	private File filesDir;

	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		filesDir = getExternalFilesDir(null);

		try {
			filesDir.createNewFile();
		} catch (IOException e) {
			e.printStackTrace();
		}

		String[] modules = { "serval", "dummy" };
		extractKernelModules(modules);

		prefs = getSharedPreferences("serval", 0);
		setContentView(R.layout.main);
		List<Fragment> fragments = new Vector<Fragment>();
		fragments.add(Fragment.instantiate(this,
				FlowTableFragment.class.getName()));
		fragments.add(Fragment.instantiate(this,
				ServiceTableFragment.class.getName()));
		servalFrag = (ServalFragment) Fragment.instantiate(this,
				ServalFragment.class.getName());
		fragments.add(servalFrag);
		fragments.add(Fragment.instantiate(this,
				TranslatorFragment.class.getName()));
		this.pagerAdapter = new PagerAdapter(super.getSupportFragmentManager(),
				fragments);
		ViewPager pager = (ViewPager) super.findViewById(R.id.pager);
		pager.setAdapter(this.pagerAdapter);
		pager.setCurrentItem(DEFAULT_IDX);

		this.moduleStatusButton = (Button) findViewById(R.id.moduleStatusToggle);
		this.moduleStatusButton.setOnClickListener(new OnClickListener() {

			@Override
			public void onClick(View v) {
				boolean isLoaded = isModuleLoaded("serval");
				boolean addPersistent = !isLoaded;
				boolean result = false;

				Log.d("Serval", "Clicked moduleStatusButton");

				if (!moduleStatusButton.isSelected()) {
					if (isLoaded) {
						setModuleLoaded(isLoaded);
						return;
					}
					result = loadKernelModule("serval");

					if (!result) {
						Toast t = Toast.makeText(getApplicationContext(),
								"Failed to load the Serval kernel module.",
								Toast.LENGTH_SHORT);
						t.show();
					}
				} else {
					stopService(new Intent(ServalActivity.this, TableService.class));
					AppHostCtrl.fini();

					if (!isLoaded) {
						setModuleLoaded(isLoaded);
						return;
					}
					result = unloadKernelModule("serval");
				}

				if (!isModuleLoaded("serval")) {
					setModuleLoaded(false);
					setUdpEncap(false);
				} else {
					setModuleLoaded(true);
					
					startService(new Intent(ServalActivity.this, TableService.class));
					AppHostCtrl.init(cbs);
					/* insert persistent rules */
					if (addPersistent) {
						Map<String, ?> idMap = prefs.getAll();
						for (String srvID : idMap.keySet()) {
							if (!(idMap.get(srvID) instanceof String))
								continue;
							String addr = (String) idMap.get(srvID);
							AppHostCtrl.performOp(getApplicationContext(),
									srvID, addr, AppHostCtrl.SERVICE_ADD);
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

				if (!isModuleLoaded("serval")) {
					setUdpEncap(false);
					return;
				}

				if (!udpEncapButton.isSelected())
					cmd = "echo 1 > /proc/sys/net/serval/udp_encap";
				else
					cmd = "echo 0 > /proc/sys/net/serval/udp_encap";

				if (!executeSuCommand(cmd)) {
					Toast t = Toast.makeText(getApplicationContext(), cmd
							+ " failed!", Toast.LENGTH_SHORT);
					t.show();
				}
				setUdpEncap(readBooleanProcEntry("/proc/sys/net/serval/udp_encap"));
			}
		});
		
		Log.d("Serval", "onCreate finished");
	}

	void extractKernelModules(final String[] modules) {
		new Thread(new Runnable() {
			@Override
			public void run() {
				for (String name : modules) {
                    String assetsName = name + "-" + getFormattedKernelVersion() + ".ko";
					final File module = new File(filesDir, name + ".ko");

					Log.d("Serval", "extracting module " + assetsName + " to "
							+ module.getAbsolutePath());

					if (module.exists())
						continue;

					try {
						BufferedInputStream in = new BufferedInputStream(
								getAssets().open(assetsName));

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

						Log.d("Serval",
								"Wrote " + tot + " bytes to "
										+ module.getAbsolutePath());

					} catch (IOException e) {
						Log.d("Serval", "Could not extract " + assetsName);
						// e.printStackTrace();
					}
				}
			}
		}).start();
	}

	public boolean loadKernelModule(final String name) {
		return executeSuCommand("insmod "
				+ new File(filesDir, name + ".ko").getAbsolutePath());
	}

	public boolean unloadKernelModule(final String name) {
		return executeSuCommand("rmmod "
				+ new File(filesDir, name).getAbsolutePath());
	}
	
	boolean executeSuCommand(final String cmd) {
		Log.d("Serval", "executing su command: " + cmd);
		return executeSuCommand(cmd, false);
	}

	public boolean executeSuCommand(final String cmd, boolean showToast) {
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
		if (showToast)
			Toast.makeText(getApplicationContext(), "'" + cmd + "' failed!",
					Toast.LENGTH_SHORT).show();

		return false;
	}

	static public boolean readBooleanProcEntry(String entry) {
		boolean isEnabled = false;
		File encap = new File(entry);

		if (encap.exists() && encap.canRead()) {
			try {
				BufferedReader in = new BufferedReader(new InputStreamReader(
						new FileInputStream(encap)));

				String line = in.readLine();

				if (line.contains("1"))
					isEnabled = true;
				in.close();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		} else {
			Log.d("Serval", "could not open " + entry);
		}
		return isEnabled;
	}

	static private boolean isModuleLoaded(String module) {
		File procModules = new File("/proc/modules");

		if (procModules.exists() && procModules.canRead()) {
			try {
				BufferedReader in = new BufferedReader(new InputStreamReader(
						new FileInputStream(procModules)));

				String line = null;
				while ((line = in.readLine()) != null) {
					if (line.contains(module)) {
						in.close();
						return true;
					}
				}
				in.close();
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
		CharSequence text = Html.fromHtml(getString(loaded ?
				R.string.module_loaded : R.string.module_unloaded));
		moduleStatusButton.setSelected(loaded);
		moduleStatusButton.setText(text);
		if (servalFrag.autoMigrationButton != null)
			servalFrag.autoMigrationButton.setChecked(ServalActivity.readBooleanProcEntry("/proc/sys/net/serval/auto_migrate"));
	}

	public void setUdpEncap(boolean on) {
		CharSequence text = Html.fromHtml(getString(on ? R.string.udp_on
				: R.string.udp_off));
		udpEncapButton.setSelected(on);
		udpEncapButton.setText(text);
	}

    /*
      This function is taken from the Android Open Source Project.
      packages/apps/Settings/src/com/android/settings/DeviceInfoSettings.java
    */
    static private String getFormattedKernelVersion() {
        String procVersionStr;

        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/version"), 256);
            try {
                procVersionStr = reader.readLine();
            } finally {
                reader.close();
            }

            final String PROC_VERSION_REGEX =
                "\\w+\\s+" + /* ignore: Linux */
                "\\w+\\s+" + /* ignore: version */
                "([^\\s]+)\\s+" + /* group 1: 2.6.22-omap1 */
                "\\(([^\\s@]+(?:@[^\\s.]+)?)[^)]*\\)\\s+" + /* group 2: (xxxxxx@xxxxx.constant) */
                "\\((?:[^(]*\\([^)]*\\))?[^)]*\\)\\s+" + /* ignore: (gcc ..) */
                "([^\\s]+)\\s+" + /* group 3: #26 */
                "(?:PREEMPT\\s+)?" + /* ignore: PREEMPT (optional) */
                "(.+)"; /* group 4: date */

            Pattern p = Pattern.compile(PROC_VERSION_REGEX);
            Matcher m = p.matcher(procVersionStr);

            if (!m.matches()) {
                Log.e("Serval", "Regex did not match on /proc/version: " + procVersionStr);
                return "Unavailable";
            } else if (m.groupCount() < 4) {
                Log.e("Serval", "Regex match on /proc/version only returned " + m.groupCount()
                      + " groups");
                return "Unavailable";
            } else {
                return (new StringBuilder(m.group(1))).toString();
            }
        } catch (IOException e) {
            Log.e("Serval",
                  "IO Exception when getting kernel version for Device Info screen",
                  e);

            return "Unavailable";
        }
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
						if (servalFrag != null && servalFrag.servicePerm != null && servalFrag.servicePerm.isChecked()) {
							Log.d("Serval", "Saving rule...");
							prefs.edit()
									.putString(
											servalFrag.editServiceText
													.getText().toString(),
											servalFrag.editIpText.getText()
													.toString()).commit();
						}
					} else
						msg = "Add service failed retval=" + retval + " "
								+ getRetvalString(retval);

					Toast t = Toast.makeText(getApplicationContext(), msg,
							Toast.LENGTH_SHORT);
					t.setGravity(Gravity.CENTER, 0, 0);
					t.show();
				}
			});
		}

		@Override
		public void onServiceRemove(long xid, final int retval,
				ServiceInfoStat[] info) {
			Map<String, ?> idMap = prefs.getAll();
			for (ServiceInfoStat i : info) {
				for (String srvID : idMap.keySet()) {
					int prefixBits = 256;
					String res[] = srvID.split(":");
					
					if (res.length == 2)
						prefixBits = Integer.parseInt(res[1]);
					
					String key = AppHostCtrl.createServiceID(res[0]).toString();
					if (key.equals(i.getServiceID().toString()) &&
							prefixBits == i.getPrefixBits()) {

						if (i.getPrefixBits() != 256) {
							key += ":" + i.getPrefixBits();
						}
						Log.v("Serval", "Remove key: " + key);
						
						prefs.edit().remove(srvID).commit();
					}
				}
			}
			runOnUiThread(new Runnable() {
				@Override
				public void run() {
					String msg;
					if (retval == RETVAL_OK) {
						msg = "Removed service";
					} else
						msg = "Remove service failed retval=" + retval + " "
								+ getRetvalString(retval);

					Toast t = Toast.makeText(getApplicationContext(), msg,
							Toast.LENGTH_LONG);
					t.setGravity(Gravity.CENTER, 0, 0);
					t.show();
				}
			});
		}

		final String DEFAULT_ID = 
			"0000000000000000000000000000000000000000000000000000000000000000";
		@Override
		public void onServiceGet(long xid, final int retval, ServiceInfo[] info) {
			for (int i = 0; i < info.length; i++) {
				Log.d("Serval", "RETRIEVED: Service " + info[i].getServiceID()
						+ "address " + info[i].getAddress());
				synchronized(TableService.LOCK) {
					boolean found = !info[i].getServiceID().toString().equals(DEFAULT_ID);
					TableService.LOCK.set(found);
					TableService.LOCK.notifyAll();
				}
			}
			
		}
		
		@Override
		public void onServiceDelayed(long xid, long pktId, ServiceID service) {
			Log.d("Serval", "Delayed resolution for pkt " + pktId + " service " + service);
		}
	};

	@Override
	protected void onStart() {
		super.onStart();
		setModuleLoaded(isModuleLoaded("serval"));
		setUdpEncap(readBooleanProcEntry("/proc/sys/net/serval/udp_encap"));

		AppHostCtrl.init(cbs);
		Log.d("Serval", "onStart finished");
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
			this.titles = ServalActivity.this.getResources().getStringArray(
					R.array.pager_titles);
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
