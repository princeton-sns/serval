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
import org.servalarch.serval.R;
import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.CompoundButton;
import android.widget.Toast;
import android.widget.ToggleButton;

public class ServalActivity extends Activity
{
	private ToggleButton moduleStatusButton;
	private File module = null;
	
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
				}

				if (!executeSuCommand(cmd)) {
					Toast t = Toast.makeText(getApplicationContext(), cmd + " failed!", 
							Toast.LENGTH_SHORT);
					t.show();
				}

				if (!isServalModuleLoaded() && isChecked)
					moduleStatusButton.setChecked(false);
				else if (isServalModuleLoaded() && !isChecked)
					moduleStatusButton.setChecked(true);
			}
		});
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
	}
	@Override
	protected void onStop() {
		super.onStop();
	}

}
