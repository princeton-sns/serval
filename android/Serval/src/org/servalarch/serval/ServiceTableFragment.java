package org.servalarch.serval;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;

import android.app.Activity;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

public class ServiceTableFragment extends Fragment {
	
	private TextView serviceTable;
	private ServiceTableThread thread;
	
	public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
		super.onCreateView(inflater, container, savedInstanceState);
		View view = inflater.inflate(R.layout.frag_service_table, container, false);
		serviceTable = (TextView) view.findViewById(R.id.service_table);
		thread = new ServiceTableThread();
		thread.start();
		
		return view;
	}
	
	@Override
	public void onDetach() {
		if (thread != null)
			thread.end();
		super.onDetach();
	}
	
	
	private class ServiceTableThread extends Thread {
		
		private boolean running = true;
		
		@Override
		public void run() {
			while(running) {
				Activity a = getActivity();
				if (a == null) {
					running = false;
					break;
				}
				a.runOnUiThread(new Runnable() {
					public void run() {
						serviceTable.setText(getTable());
					}
				});
				try {
					sleep(1000);
				} 
				catch (InterruptedException e) {
				}
			}
		}
		
		public String getTable() {
			File table = new File("/proc/net/serval/service_table");
			if (!table.exists())
				return getString(R.string.no_service_table);
			else {
				StringBuilder builder = new StringBuilder();
				try {
					BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(table)));

					String line = null;
					while ((line = in.readLine()) != null) {
						builder.append(line + "\n");
					}
				} catch (Exception e) {
					return getString(R.string.no_service_table);
				}
				return builder.toString();
			}
		}
		
		public void end() {
			this.running = false;
		}
	}
}
