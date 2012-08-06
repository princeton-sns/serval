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
import java.util.Map;

import org.servalarch.servalctrl.HostCtrlCallbacks;
import org.servalarch.servalctrl.ServiceInfo;
import org.servalarch.servalctrl.ServiceInfoStat;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.util.Log;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.Toast;
import android.widget.ToggleButton;

public class ServalFragment extends Fragment {
	private ToggleButton moduleStatusButton;
	private ToggleButton udpEncapButton;
	private Button addServiceButton, removeServiceButton;
	private EditText editServiceText, editIpText;
	private File module = null;
	
	private SharedPreferences prefs;
	private View view;
	
	public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
		super.onCreateView(inflater, container, savedInstanceState);
		prefs = getActivity().getSharedPreferences("serval", 0);
		view = inflater.inflate(R.layout.frag_serval, container, false);
		File filesDir = getActivity().getExternalFilesDir(null);
		try {
			filesDir.createNewFile();
		} catch (IOException e) {
			e.printStackTrace();
		}
		module = new File(filesDir, "serval.ko");
		
		editServiceText = (EditText) view.findViewById(R.id.edit_service_field);
		editIpText = (EditText) view.findViewById(R.id.ip_input_field);
		/*editServiceText.setOnEditorActionListener(new OnEditorActionListener() {
			@Override
			public boolean onEditorAction(TextView v, int actionId,
					KeyEvent event) {
				
				System.out.println("TextView text is " + v.getText());
				return false;
			}
			
		});*/
		addServiceButton = (Button) view.findViewById(R.id.add_service_button);
		addServiceButton.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View arg0) {
				AppHostCtrl.performOp(getActivity().getApplicationContext(), editServiceText.getText().toString(), 
						editIpText.getText().toString(), AppHostCtrl.SERVICE_ADD);
			}
		});
		removeServiceButton = (Button) view.findViewById(R.id.remove_service_button);
		removeServiceButton.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View arg0) {
				AppHostCtrl.performOp(getApplicationContext(), editServiceText.getText().toString(), 
						editIpText.getText().toString(), AppHostCtrl.SERVICE_REMOVE);
			}
		});
		
		this.moduleStatusButton = (ToggleButton) view.findViewById(R.id.moduleStatusToggle);
		this.moduleStatusButton.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
			@Override
			public void onCheckedChanged(CompoundButton buttonView,
					boolean isChecked) {
				boolean isLoaded = isServalModuleLoaded();
				boolean addPersistent = !isLoaded;
				String cmd;

				if (isChecked) {
					if (isLoaded)
						return;

					cmd = "insmod " + module.getAbsolutePath();
					
				} else {
					if (!isLoaded)
						return;
					cmd = "rmmod serval";
					

					AppHostCtrl.fini();					
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
		
		this.udpEncapButton = (ToggleButton) view.findViewById(R.id.udpEncapToggle);
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
		
		return view;
	}
	
	private Context getApplicationContext() {
		return getActivity().getApplicationContext();
	}
	
	
	private boolean extractKernelModule(final File module) {
		if (module.exists())
			return true;

		try {
			BufferedInputStream in = new BufferedInputStream(getActivity().getAssets().open("serval.ko"));

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

	private final HostCtrlCallbacks cbs = new HostCtrlCallbacks() {
		@Override
		public void onServiceAdd(long xid, final int retval, ServiceInfo[] info) {
			getActivity().runOnUiThread(new Runnable() {
				@Override
				public void run() {
					String msg;
					if (retval == RETVAL_OK) {
						msg = "Added service";
						if (((ToggleButton) view.findViewById(R.id.servicePerm)).isChecked()) {
							Log.d("Serval", "Saving rule...");
							prefs.edit().putString(editServiceText.getText().toString(), 
									editIpText.getText().toString()).commit();
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
			getActivity().runOnUiThread(new Runnable() {
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
}
