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

public class FlowTableFragment extends Fragment {
	
	private static final String FLOW_TABLE = "/proc/net/serval/flow_table";
	
	private TextView flowTable;
	private FlowTableThread thread;
	
	public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
		super.onCreateView(inflater, container, savedInstanceState);
		View view = inflater.inflate(R.layout.frag_flow_table, container, false);
		flowTable = (TextView) view.findViewById(R.id.flow_table);
		thread = new FlowTableThread();
		thread.start();
		
		return view;
	}
	
	@Override
	public void onDetach() {
		if (thread != null)
			thread.end();
		super.onDetach();
	}
	
	
	private class FlowTableThread extends Thread {
		
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
						flowTable.setText(getTable());
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
			File table = new File(FLOW_TABLE);
			if (!table.exists())
				return getString(R.string.no_flow_table);
			else {
				StringBuilder builder = new StringBuilder();
				try {
					BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(table)));

					String line = null;
					while ((line = in.readLine()) != null) {
						builder.append(line + "\n");
					}
					in.close();
				} catch (Exception e) {
					return getString(R.string.no_flow_table);
				}
				return builder.toString();
			}
		}
		
		public void end() {
			this.running = false;
		}
	}
}
