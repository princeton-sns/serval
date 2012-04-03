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

import org.servalarch.servalctrl.HostCtrl.HostCtrlException;
import org.servalarch.servalctrl.HostCtrlCallbacks;
import org.servalarch.servalctrl.LocalHostCtrl;
import org.servalarch.servalctrl.ServiceInfo;
import org.servalarch.servalctrl.ServiceInfoStat;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.ActivityManager.RunningServiceInfo;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.TextView.OnEditorActionListener;
import android.widget.Toast;
import android.widget.ToggleButton;

public class ServalActivity extends Activity
{
	private ToggleButton moduleStatusButton;
	private ToggleButton udpEncapButton;
	private ToggleButton translatorButton;
	private Button addServiceButton, removeServiceButton;
	private EditText editServiceText, editIpText;
	private File module = null;
	
	private SharedPreferences prefs;
	
	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		prefs = getSharedPreferences("serval", 0);
		setContentView(R.layout.main);
		File filesDir = getExternalFilesDir(null);
		try {
			filesDir.createNewFile();
		} catch (IOException e) {
			e.printStackTrace();
		}
		module = new File(filesDir, "serval.ko");
		
		editServiceText = (EditText) findViewById(R.id.edit_service_field);
		editIpText = (EditText) findViewById(R.id.ip_input_field);
		editServiceText.setOnEditorActionListener(new OnEditorActionListener() {
			@Override
			public boolean onEditorAction(TextView v, int actionId,
					KeyEvent event) {
				
				System.out.println("TextView text is " + v.getText());
				return false;
			}
			
		});
		addServiceButton = (Button)findViewById(R.id.add_service_button);
		addServiceButton.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View arg0) {
				AppHostCtrl.performOp(getApplicationContext(), editServiceText.getText().toString(), 
						editIpText.getText().toString(), AppHostCtrl.SERVICE_ADD);
			}
		});
		removeServiceButton = (Button)findViewById(R.id.remove_service_button);
		removeServiceButton.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View arg0) {
				AppHostCtrl.performOp(getApplicationContext(), editServiceText.getText().toString(), 
						editIpText.getText().toString(), AppHostCtrl.SERVICE_REMOVE);
			}
		});
		
		this.moduleStatusButton = (ToggleButton) findViewById(R.id.moduleStatusToggle);
		this.moduleStatusButton.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
			@Override
			public void onCheckedChanged(CompoundButton buttonView,
					boolean isChecked) {
				boolean isLoaded = isServalModuleLoaded();
				String cmd;

				if (isChecked) {
					if (isLoaded)
						return;

					cmd = "insmod " + module.getAbsolutePath();
				} else {
					if (!isLoaded)
						return;
					cmd = "rmmod serval";
					
					if (AppHostCtrl.hc != null) {
						AppHostCtrl.hc.dispose();
						AppHostCtrl.hc = null;
					}
						
				}

				if (!executeSuCommand(cmd)) {
					Toast t = Toast.makeText(getApplicationContext(), cmd + " failed!", 
							Toast.LENGTH_SHORT);
					t.show();
				}

				if (!isServalModuleLoaded()) {
					if (isChecked)
						moduleStatusButton.setChecked(false);
					if (udpEncapButton.isChecked())
						udpEncapButton.setChecked(false);
				} else if (isServalModuleLoaded()) {
					 if (!isChecked)
						 moduleStatusButton.setChecked(true);
					 if (AppHostCtrl.hc == null) {
						 try {
							 AppHostCtrl.hc = new LocalHostCtrl(cbs);
							} catch (HostCtrlException e) {
								e.printStackTrace();
							}
					 }
				}
			}
		});
		
		this.udpEncapButton = (ToggleButton) findViewById(R.id.udpEncapToggle);
		this.udpEncapButton.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
			@Override
			public void onCheckedChanged(CompoundButton buttonView,
					boolean isChecked) {
				String cmd;
				
				if (!isServalModuleLoaded()) {
					if (isChecked)
						buttonView.setChecked(false);
					return;
				}
				
				if (isChecked)
					 cmd = "echo 1 > /proc/sys/net/serval/udp_encap";
				else
					 cmd = "echo 0 > /proc/sys/net/serval/udp_encap";

				if (!executeSuCommand(cmd)) {
					Toast t = Toast.makeText(getApplicationContext(), cmd + " failed!", 
							Toast.LENGTH_SHORT);
					t.show();
				}
				if (!isUdpEncapEnabled() && isChecked)
					udpEncapButton.setChecked(false);
				else if (isUdpEncapEnabled() && !isChecked)
					udpEncapButton.setChecked(true);
			}
		});
		this.translatorButton = (ToggleButton) findViewById(R.id.translatorToggle);
		this.translatorButton.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
			@Override
			public void onCheckedChanged(CompoundButton buttonView,
					boolean isChecked) {
				if (isChecked) {
					startService(new Intent(ServalActivity.this, TranslatorService.class));
					executeSuCommand("iptables -t nat -A OUTPUT -p tcp --destination 0.0.0.0/0.0.0.0 --dport 80 -m tcp --syn -j REDIRECT --to-ports 8080");
					executeSuCommand("iptables -t nat -A OUTPUT -p tcp --destination 0.0.0.0/0.0.0.0 --dport 443 -m tcp --syn -j REDIRECT --to-ports 8080");
				} else {
					stopService(new Intent(ServalActivity.this, TranslatorService.class));
					executeSuCommand("iptables -t nat -D OUTPUT -p tcp --destination 0.0.0.0/0.0.0.0 --dport 80 -m tcp --syn -j REDIRECT --to-ports 8080");
					executeSuCommand("iptables -t nat -D OUTPUT -p tcp --destination 0.0.0.0/0.0.0.0 --dport 443 -m tcp --syn -j REDIRECT --to-ports 8080");
				}
			}
		});
	}
	
	private boolean isTranslatorRunning() {
	    ActivityManager manager = (ActivityManager) getSystemService(ACTIVITY_SERVICE);
	    for (RunningServiceInfo service : manager.getRunningServices(Integer.MAX_VALUE)) {
	        if ("org.servalarch.serval.TranslatorService".equals(service.service.getClassName())) {
	            return true;
	        }
	    }
	    return false;
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

	private boolean executeSuCommand(final String cmd) {
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
						if (((ToggleButton) findViewById(R.id.servicePerm)).isChecked()) {
							Log.d("Serval", "Saving rule...");
							prefs.edit().putString(editServiceText.getText().toString(), 
									editIpText.getText().toString()).commit();
						}
					}
					else
						msg = "Add service failed retval=" + retval + " " + getRetvalString(retval);
					
					Toast t = Toast.makeText(getApplicationContext(), msg, 
							Toast.LENGTH_LONG);
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
						prefs.edit().remove(editServiceText.getText().toString()).commit();
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

		if (isServalModuleLoaded())
			moduleStatusButton.setChecked(true);
		else
			moduleStatusButton.setChecked(false);
		
		if (isUdpEncapEnabled())
			udpEncapButton.setChecked(true);
		else
			udpEncapButton.setChecked(false);
		
		if (isTranslatorRunning())
			translatorButton.setChecked(true);
		else
			translatorButton.setChecked(false);
		
		try {
			AppHostCtrl.hc = new LocalHostCtrl(cbs);
		} catch (HostCtrlException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	@Override
	protected void onStop() {
		super.onStop();
		if (AppHostCtrl.hc != null)
			AppHostCtrl.hc.dispose();
	}

}
