package org.servalarch.serval;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.text.Html;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;

public class FlowTableFragment extends Fragment {
	
	private static final String FLOW_TABLE = "/proc/net/serval/flow_table";
	private static final String FMT_SOURCE = "<b>Source:</b> %d (%s)";
	private static final String FMT_DEST = "<b>Dest :</b> %d (%s)";
	private static final String FMT_STATE = "<b>State:</b> %s (%s)";
	
	private ListView flowTable;
	private FlowTableThread thread;
	
	public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
		super.onCreateView(inflater, container, savedInstanceState);
		flowTable = (ListView) inflater.inflate(R.layout.frag_flow_table, container, false);
		thread = new FlowTableThread();
		thread.start();
		
		return flowTable;
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
						flowTable.setAdapter(getTable());
					}
				});
				try {
					sleep(1000);
				} 
				catch (InterruptedException e) {
				}
			}
		}
		
		public FlowTableAdapter getTable() {
			File table = new File(FLOW_TABLE);
			List<FlowTableItem> ret = new ArrayList<FlowTableItem>();
			if (!table.exists()) {
				return new FlowTableAdapter(getActivity(), R.id.flow_table, ret);
			}
			else {
				try {
					BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(table)));

					String line = in.readLine();
					while ((line = in.readLine()) != null) {
						ret.add(new FlowTableItem(line.split("\\s+")));
					}
					in.close();
				} catch (Exception e) {
					e.printStackTrace();
					ret.clear();
				}
				return new FlowTableAdapter(getActivity(), R.id.flow_table, ret);
			}
		}
		
		public void end() {
			this.running = false;
		}
	}
	
	private class FlowTableAdapter extends ArrayAdapter<FlowTableItem> {
		
		public FlowTableAdapter(Context context, int id, List<FlowTableItem> items) {
			super(context, id, items);
		}
		
		public View getView(int pos, View convert, ViewGroup parent) {
			View v = convert;
			if (v == null) {
				v = getActivity().getLayoutInflater().inflate(R.layout.flow_table_item, null);
			}
			FlowTableItem i = getItem(pos);
			CharSequence src = Html.fromHtml(String.format(FMT_SOURCE, i.srcFlow, i.srcIP));
			CharSequence dest = Html.fromHtml(String.format(FMT_DEST, i.destFlow, i.destIP));
			CharSequence state = Html.fromHtml(String.format(FMT_STATE, i.state, i.iface));
			((TextView) v.findViewById(R.id.source)).setText(src);
			((TextView) v.findViewById(R.id.dest)).setText(dest);
			((TextView) v.findViewById(R.id.state)).setText(state);
			
			return v;
		}
	}
	
	private static class FlowTableItem {
		
		private final long srcFlow;
		private final long destFlow;
		private final String srcIP;
		private final String destIP;
		private final String state;
		private final String iface;
		
		public FlowTableItem(String[] args) {
			this.srcFlow = Long.parseLong(args[0]);
			this.destFlow = Long.parseLong(args[1]);
			this.srcIP = args[2].trim();
			this.destIP = args[3].trim();
			this.state = args[4].trim();
			this.iface = args[5].trim();
		}
	}
}
