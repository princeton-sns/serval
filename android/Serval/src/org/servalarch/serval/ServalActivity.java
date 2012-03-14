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
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.servalarch.net.ServiceID;
import org.servalarch.serval.R;
import org.servalarch.servalctrl.HostCtrl;
import org.servalarch.servalctrl.HostCtrl.HostCtrlException;
import org.servalarch.servalctrl.HostCtrlCallbacks;
import org.servalarch.servalctrl.LocalHostCtrl;
import org.servalarch.servalctrl.ServiceInfo;
import org.servalarch.servalctrl.ServiceInfoStat;

import android.app.Activity;
import android.os.Bundle;
import android.text.InputFilter;
import android.text.InputType;
import android.text.Spanned;
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
	private Button addServiceButton, removeServiceButton;
	private EditText editServiceText, editIpText;
	private File module = null;
	private HostCtrl hc = null;
	private static final int SERVICE_ADD = 0;
	private static final int SERVICE_REMOVE = 1;
	
	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
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
				performOp(editServiceText.getText().toString(), 
						editIpText.getText().toString(), SERVICE_ADD);
			}
		});
		removeServiceButton = (Button)findViewById(R.id.remove_service_button);
		removeServiceButton.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View arg0) {
				performOp(editServiceText.getText().toString(), 
						editIpText.getText().toString(), SERVICE_REMOVE);
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
					
					if (hc != null) {
						hc.dispose();
						hc = null;
					}
						
				}

				if (!executeSuCommand(cmd)) {
					Toast t = Toast.makeText(getApplicationContext(), cmd + " failed!", 
							Toast.LENGTH_SHORT);
					t.show();
				}

				if (!isServalModuleLoaded() && isChecked)
					moduleStatusButton.setChecked(false);
				else if (isServalModuleLoaded()) {
					 if (!isChecked)
						 moduleStatusButton.setChecked(true);
					 if (hc == null) {
						 try {
								hc = new LocalHostCtrl(cbs);
							} catch (HostCtrlException e) {
								e.printStackTrace();
							}
					 }
				}
			}
		});
	}
	
	private ServiceID createServiceID(String serviceStr) {
		ServiceID sid = null;
		
		if (serviceStr.length() > 2 && serviceStr.charAt(0) == '0' && serviceStr.charAt(1) == 'x') {
			// Hex string
			if (!serviceStr.matches("^[a-fA-F0-9]{1,40}$"))
				return null;
	
			byte[] rawID = new byte[(serviceStr.length() - 2) / 2];
			
			for (int i = 2; i < serviceStr.length(); i += 2) {
				/*
				byte b;
				Character.digit(serviceStr.charAt(i), 16);
				if (serviceStr.length())
				serviceStr.charAt(i+1)
				*/
			}
			sid = new ServiceID();
		} else {
			// Decimal string
			if (!serviceStr.matches("^[0-9]{1,20}$"))
				return null;
			sid = new ServiceID(Integer.parseInt(serviceStr));
		}
		return sid;
	}
	
	private InetAddress createAddress(String ipStr) {
		InetAddress addr = null;
		try {
			addr = InetAddress.getByName(ipStr);
		} catch (UnknownHostException e) {
			
		}
		return addr;
	}
	
	private void performOp(String serviceStr, String ipStr, int op) {
		ServiceID sid;
		InetAddress addr;
		
		sid = createServiceID(serviceStr);
		
		if (sid == null) {
			Toast t = Toast.makeText(getApplicationContext(), "Not a valid serviceID", 
					Toast.LENGTH_SHORT);
			t.show();
			return;
		}
		
		addr = createAddress(ipStr);
		
		if (addr == null) {
			Toast t = Toast.makeText(getApplicationContext(), "Not a valid IP address", 
					Toast.LENGTH_SHORT);
			t.show();
			return;
		}
		
		switch (op) {
		case SERVICE_ADD:
			Log.d("Serval", "adding service " + sid + " address " + addr);
			hc.addService(sid, 0, 1, 1, addr);
			break;
		case SERVICE_REMOVE:
			hc.removeService(sid, 0, addr);
			break;
		default:
			break;
		}
	}
	private boolean extractKernelModule(File module) {
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

	private boolean executeSuCommand(String cmd) {
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

	private boolean isServalModuleLoaded() {
		boolean moduleIsLoaded = false;

		File procModules = new File("/proc/modules");

		if (procModules.exists() && procModules.canRead()) {
			try {
				BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(procModules)));

				String line = in.readLine();

				if (line.contains("serval")) {
					moduleIsLoaded = true;
				}
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		} else {
			Log.d("Serval", "could not open /proc/modules");
		}
		return moduleIsLoaded;
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
					if (retval == RETVAL_OK) 
						msg = "Added service";
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
					if (retval == RETVAL_OK) 
						msg = "Removed service";
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
		public void onServiceGet(long xid, int retval, ServiceInfo[] info) {
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
		
		try {
			hc = new LocalHostCtrl(cbs);
		} catch (HostCtrlException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	@Override
	protected void onStop() {
		super.onStop();
		if (hc != null)
			hc.dispose();
	}

}
