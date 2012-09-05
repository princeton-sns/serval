/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.serval;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;

import android.app.Activity;
import android.content.Context;
import android.graphics.Color;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.text.Html;
import android.util.Log;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.PopupWindow;
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
	
	private class OnMigrateClick implements OnClickListener {

		@Override
		public void onClick(View v) {
			final long flow = Long.valueOf((String) v.getTag()).longValue();
			ViewGroup migrateView = (ViewGroup) getActivity().getLayoutInflater().inflate(R.layout.migrate_popup, null);
			final PopupWindow popup = new PopupWindow(migrateView);
			popup.setTouchable(true);
			popup.setFocusable(true);
			List<String> choices = new ArrayList<String>();
			try {
				Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
				ArrayList<NetworkInterface> netsList = Collections.list(nets);
				for (NetworkInterface iface : netsList) {
					if (iface.isUp()) {
						choices.add(iface.getName());
					}
				}
			}
			catch (Exception e) {	
			}
			choices.add("Cancel");
			ArrayAdapter<String> adapter = new ArrayAdapter<String>(getActivity(), R.layout.migrate_item, choices);
			ListView list = (ListView) popup.getContentView().findViewById(R.id.migrate_list);
			list.setAdapter(adapter);
			list.setOnItemClickListener(new OnItemClickListener() {

				@Override
				public void onItemClick(AdapterView<?> parent, View view,
						int pos, long id) {
					String iface = ((TextView) view).getText().toString();
					if (!iface.equals("Cancel")) {
						AppHostCtrl.hc.migrateFlow(flow, iface);
					}
					popup.dismiss();
				}
				
			});
			popup.setWindowLayoutMode(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
			popup.showAtLocation(flowTable, Gravity.CENTER, 0, 0);
			
			Log.d("Popup", "W: " + popup.getWidth());
		}
		
	}
	
	
	private class FlowTableThread extends Thread {
		
		private boolean running = true;
		private FlowTableAdapter adapter;
		
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
						getTable();
					}
				});
				try {
					sleep(1000);
				} 
				catch (InterruptedException e) {
				}
			}
		}
		
		public void getTable() {
			File table = new File(FLOW_TABLE);
			if (adapter == null) {
				List<FlowTableItem> items = new ArrayList<FlowTableItem>();
				adapter = new FlowTableAdapter(getActivity(), R.id.flow_table, items);
				flowTable.setAdapter(adapter);
			}
			adapter.startRound();
			if (!table.exists()) {
				adapter.clear();
			}
			else {
				try {
					BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(table)));

					String line = in.readLine();
					while ((line = in.readLine()) != null) {
						adapter.add(new FlowTableItem(line.split("\\s+")));
					}
					in.close();
				} catch (Exception e) {
					e.printStackTrace();
					adapter.clear();
				}
			}
			adapter.endRound();
			adapter.notifyDataSetChanged();
		}
		
		public void end() {
			this.running = false;
		}
	}
	
	private class FlowTableAdapter extends ArrayAdapter<FlowTableItem> {
		
		private FlowTableItem[] items;
		private HashSet<FlowTableItem> set;
		
		public FlowTableAdapter(Context context, int id, List<FlowTableItem> items) {
			super(context, id, items);
			this.items = new FlowTableItem[items.size()];
			this.set = new HashSet<FlowTableItem>();
		}
		
		@Override
		public int getCount() {
			return items.length;
		}
		
		public void startRound() {
			this.set.clear();
		}
		
		@Override
		public void add(FlowTableItem item) {
			this.set.add(item);
		}
		
		public void endRound() {
			this.items = new FlowTableItem[set.size()];
			this.set.toArray(this.items);
		}
		
		@Override
		public void clear() {
			super.clear();
			this.items = new FlowTableItem[0];
			this.set.clear();
		}
		
		public View getView(int pos, View convert, ViewGroup parent) {
			View v = convert;
			if (v == null) {
				v = getActivity().getLayoutInflater().inflate(R.layout.flow_table_item, null);
			}
			FlowTableItem i = items[pos];
			v.setBackgroundColor(pos % 2 == 0 ? Color.BLACK : Color.DKGRAY);
			CharSequence src = Html.fromHtml(String.format(FMT_SOURCE, i.srcFlow, i.srcIP));
			CharSequence dest = Html.fromHtml(String.format(FMT_DEST, i.destFlow, i.destIP));
			CharSequence state = Html.fromHtml(String.format(FMT_STATE, i.state, i.iface));
			((TextView) v.findViewById(R.id.source)).setText(src);
			((TextView) v.findViewById(R.id.dest)).setText(dest);
			((TextView) v.findViewById(R.id.state)).setText(state);
			v.findViewById(R.id.migrate).setTag(Long.toString(i.srcFlow));
			v.findViewById(R.id.migrate).setOnClickListener(new OnMigrateClick());
			
			return v;
		}
	}
	
	private static class FlowTableItem implements Comparable<FlowTableItem> {
		
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
		
		@Override
		public int hashCode() {
			return (int)this.srcFlow;
		}
		
		@Override
		public boolean equals(Object o) {
			if (o != null && o instanceof FlowTableItem) {
				FlowTableItem item = (FlowTableItem) o;
				return item.srcFlow == this.srcFlow && item.destFlow == this.destFlow;
			}
			return false;
		}

		@Override
		public int compareTo(FlowTableItem item) {
			if (this.srcFlow < item.srcFlow)
				return -1;
			else if (this.srcFlow > item.srcFlow)
				return 1;
			else
				return (int)(this.destFlow - item.destFlow);
		}
		
		@Override
		public String toString() {
			return "{" + srcFlow + " => " + destFlow +"}";
		}
	}
}
